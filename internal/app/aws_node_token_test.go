package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	awscloud "github.com/inguardians/peirates/internal/cloud/aws"
	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
	"github.com/inguardians/peirates/internal/ui"
)

func nodeTokenFixture() awscloud.NodeTokenResult {
	return awscloud.NodeTokenResult{Token: "k8s-aws-v1.secret", ClusterName: "test-cluster", Region: "us-east-1", RoleIdentity: "arn:aws:iam::123456789012:role/worker", RoleName: "worker", InstanceID: "i-0123456789abcdef0", PrivateDNSName: "ip-10-0-0-1.ec2.internal", RegionSource: "IMDS", ClusterSource: "EC2 instance tags", AcquiredAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute)}
}

func stubNodeTokenOperations(t *testing.T) {
	t.Helper()
	oldGenerate, oldResolve, oldVerify := generateAWSNodeToken, resolveAWSNodeTokenTarget, verifyAWSNodeToken
	t.Cleanup(func() {
		generateAWSNodeToken, resolveAWSNodeTokenTarget, verifyAWSNodeToken = oldGenerate, oldResolve, oldVerify
	})
	generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
		return nodeTokenFixture(), nil
	}
	resolveAWSNodeTokenTarget = func(cfg ServerInfo) (ServerInfo, error) { cfg.CACertData = "trusted-ca"; return cfg, nil }
	verifyAWSNodeToken = func(context.Context, model.ServerInfo, string) (kube.NodeTokenIdentity, error) {
		return kube.NodeTokenIdentity{Username: "system:node:ip-10-0-0-1.ec2.internal", Groups: []string{"system:nodes", "system:authenticated"}}, nil
	}
}

func TestAWSNodeTokenModes(t *testing.T) {
	for _, test := range []struct {
		name             string
		args             []string
		verify, activate bool
		invalid          bool
	}{
		{"default", nil, true, true, false},
		{"discovery-options", []string{"--region", "us-east-1"}, true, true, false},
		{"check", []string{"--check"}, false, false, false},
		{"verify", []string{"--verify"}, true, false, false},
		{"activate", []string{"--activate"}, true, true, false},
		{"verify-and-activate", []string{"--verify", "--activate"}, true, true, false},
		{"activate-and-verify", []string{"--activate", "--verify"}, true, true, false},
		{"disabled-activation", []string{"--activate=false"}, false, false, false},
		{"disabled-check", []string{"--check=false"}, true, true, false},
		{"disabled-verify", []string{"--verify=false"}, true, true, false},
		{"check-disabled-activation", []string{"--check", "--activate=false"}, false, false, false},
		{"check-and-verify", []string{"--check", "--verify"}, false, false, true},
		{"verify-and-check", []string{"--verify", "--check"}, false, false, true},
		{"check-and-activate", []string{"--check", "--activate"}, false, false, true},
		{"activate-and-check", []string{"--activate", "--check"}, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubNodeTokenOperations(t)
			selection, err := parseAWSNodeTokenOptions(test.args)
			if (err != nil) != test.invalid {
				t.Fatalf("parse error = %v, want invalid = %t", err, test.invalid)
			}
			if !test.invalid && (selection.verify != test.verify || selection.activate != test.activate) {
				t.Fatalf("mode = verify:%t activate:%t", selection.verify, selection.activate)
			}
			for _, interactive := range []bool{false, true} {
				session := NewSession(ServerInfo{Token: "original", Namespace: "app", ClientCertData: "cert", ClientKeyData: "key"})
				session.Interactive = interactive
				original := session.Connection
				generated, verified := 0, 0
				generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
					generated++
					return nodeTokenFixture(), nil
				}
				verifyAWSNodeToken = func(context.Context, model.ServerInfo, string) (kube.NodeTokenIdentity, error) {
					verified++
					return kube.NodeTokenIdentity{Username: "system:node:" + nodeTokenFixture().PrivateDNSName, Groups: []string{"system:nodes"}}, nil
				}
				var output bytes.Buffer
				requestAWSNodeToken(session, test.args, &output)
				if test.invalid {
					if generated != 0 || verified != 0 || session.Connection != original || len(session.AWSNodeTokens) != 0 || !strings.Contains(output.String(), "cannot be combined") {
						t.Fatalf("conflicting modes performed work: %s", &output)
					}
					continue
				}
				if generated != 1 || len(session.AWSNodeTokens) != 1 || (verified == 1) != test.verify {
					t.Fatalf("generation/verification counts = %d/%d, entries = %d", generated, verified, len(session.AWSNodeTokens))
				}
				if test.activate {
					if session.Connection.Token != nodeTokenFixture().Token || session.Connection.ActiveTokenKind != "eks-node" || session.Connection.ClientCertData != "" || session.Connection.ClientKeyData != "" || session.Connection.Namespace != original.Namespace {
						t.Fatalf("activation failed: %s", &output)
					}
				} else if session.Connection != original {
					t.Fatalf("non-activating mode changed the active connection: %s", &output)
				}
			}
		})
	}
}

func TestAWSNodeTokenCheckGenerationAndRetention(t *testing.T) {
	stubNodeTokenOperations(t)
	verifyAWSNodeToken = func(context.Context, model.ServerInfo, string) (kube.NodeTokenIdentity, error) {
		t.Fatal("--check attempted identity verification")
		return kube.NodeTokenIdentity{}, nil
	}
	for _, interactive := range []bool{false, true} {
		session := NewSession(ServerInfo{APIServer: "https://api.example", Token: "original", Namespace: "application"})
		session.Interactive = interactive
		session.AWSCredentials.AccessKeyID = "ambient"
		session.AssumedAWSRole.AccessKeyID = "assumed"
		original := session.Connection
		calls := 0
		generateAWSNodeToken = func(_ context.Context, options awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
			calls++
			if options.ClusterName != "" || options.Region != "" || options.AllowIMDSv1 || string(options.TrustedCA) != "trusted-ca" || options.APIEndpoint != original.APIServer {
				t.Fatalf("default discovery options: %#v", options)
			}
			return nodeTokenFixture(), nil
		}
		var out bytes.Buffer
		requestAWSNodeToken(session, []string{"--check"}, &out)
		if calls != 1 || len(session.AWSNodeTokens) != 1 || len(session.ServiceAccounts) != 0 || session.Connection != original || !strings.Contains(out.String(), "Bearer token: k8s-aws-v1.secret") {
			t.Fatalf("check changed session or failed: %s", &out)
		}
		generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
			result := nodeTokenFixture()
			result.Token = "replacement-secret"
			return result, nil
		}
		requestAWSNodeToken(session, []string{"--check"}, io.Discard)
		if len(session.AWSNodeTokens) != 1 {
			t.Fatal("regeneration duplicated the retained identity")
		}
		generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
			return awscloud.NodeTokenResult{}, errors.New("metadata unavailable")
		}
		requestAWSNodeToken(session, []string{"--check"}, io.Discard)
		for _, entry := range session.AWSNodeTokens {
			if entry.Token != "replacement-secret" {
				t.Fatal("failure replaced the retained credential")
			}
		}
	}
}

func TestAWSNodeTokenVerificationAndActivation(t *testing.T) {
	for _, test := range []struct {
		name, username     string
		groups             []string
		verifyErr          error
		activate, verified bool
	}{
		{"verify", "system:node:ip-10-0-0-1.ec2.internal", []string{"system:nodes"}, nil, false, true},
		{"activate", "system:node:ip-10-0-0-1.ec2.internal", []string{"system:nodes"}, nil, true, true},
		{"unproven-instance", "system:node:other", []string{"system:nodes"}, nil, false, true},
		{"wrong-user", "system:serviceaccount:default:worker", []string{"system:nodes"}, nil, true, false},
		{"missing-group", "system:node:worker", []string{"system:authenticated"}, nil, true, false},
		{"forbidden", "", nil, errors.New("identity inspection denied"), true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubNodeTokenOperations(t)
			session := NewSession(ServerInfo{APIServer: "https://api.example", Token: "old-token", TokenName: "old", ClientCertData: "old-cert", ClientKeyData: "old-key", ClientCertName: "cert", Namespace: "app"})
			original := session.Connection
			verifyAWSNodeToken = func(_ context.Context, cfg model.ServerInfo, token string) (kube.NodeTokenIdentity, error) {
				if cfg.APIServer != original.APIServer || token != nodeTokenFixture().Token {
					t.Fatal("verification used wrong target or credential")
				}
				return kube.NodeTokenIdentity{Username: test.username, Groups: test.groups}, test.verifyErr
			}
			args := []string{"--verify"}
			if test.activate {
				args = nil
			}
			var out bytes.Buffer
			requestAWSNodeToken(session, args, &out)
			if len(session.AWSNodeTokens) != 1 {
				t.Fatalf("verification retained %d entries, expected one: %s", len(session.AWSNodeTokens), &out)
			}
			for _, entry := range session.AWSNodeTokens {
				if entry.Verified != test.verified {
					t.Fatalf("verification state: %s", &out)
				}
				if entry.InstanceMatched != (test.verified && test.name != "unproven-instance") {
					t.Fatalf("incorrect instance association: %s", &out)
				}
			}
			if test.activate && test.verified {
				if session.Connection.Token != nodeTokenFixture().Token || session.Connection.Namespace != "app" || session.Connection.ClientCertData != "" || session.Connection.ClientKeyData != "" || session.Connection.ClientCertName != "" || session.Connection.ActiveTokenKind != "eks-node" || session.Connection.ActiveTokenExpiresAt.IsZero() {
					t.Fatalf("bad active credential: %s", &out)
				}
			} else if session.Connection != original {
				t.Fatal("verification/failure changed active connection")
			}
		})
	}
}

func TestAWSNodeTokenTargetErrorsAndOptions(t *testing.T) {
	stubNodeTokenOperations(t)
	for _, test := range []struct {
		name      string
		args      []string
		targetErr error
		calls     int
	}{
		{"help", []string{"--help"}, nil, 0},
		{"invalid", []string{"--bad"}, nil, 0},
		{"positional", []string{"unexpected"}, nil, 0},
		{"mismatch", nil, kube.ErrNodeTokenTargetMismatch, 0},
		{"missing-connection-check", []string{"--check"}, kube.ErrNodeTokenTargetUnavailable, 1},
		{"missing-connection-default-activation", nil, kube.ErrNodeTokenTargetUnavailable, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			resolveAWSNodeTokenTarget = func(cfg model.ServerInfo) (model.ServerInfo, error) { return cfg, test.targetErr }
			generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
				calls++
				return nodeTokenFixture(), nil
			}
			verifyAWSNodeToken = func(context.Context, model.ServerInfo, string) (kube.NodeTokenIdentity, error) {
				t.Fatal("unexpected verification")
				return kube.NodeTokenIdentity{}, nil
			}
			session := NewSession(ServerInfo{})
			requestAWSNodeToken(session, test.args, io.Discard)
			if calls != test.calls || session.Connection.Token != "" {
				t.Fatalf("calls=%d, active token set=%t", calls, session.Connection.Token != "")
			}
		})
	}
	selection, err := parseAWSNodeTokenOptions([]string{"--cluster-name", "override", "--region", "us-west-2", "--allow-imdsv1", "--activate"})
	if err != nil || selection.ClusterName != "override" || selection.Region != "us-west-2" || !selection.AllowIMDSv1 || !selection.verify || !selection.activate {
		t.Fatalf("options: %+v %v", selection, err)
	}
}

func TestAWSNodeTokenRejectsExpiredGeneration(t *testing.T) {
	stubNodeTokenOperations(t)
	generateAWSNodeToken = func(context.Context, awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
		result := nodeTokenFixture()
		result.ExpiresAt = time.Now().Add(-time.Minute)
		return result, nil
	}
	session := NewSession(ServerInfo{Token: "original"})
	var out bytes.Buffer
	requestAWSNodeToken(session, nil, &out)
	if len(session.AWSNodeTokens) != 0 || session.Connection.Token != "original" || strings.Contains(out.String(), "k8s-aws-v1.secret") {
		t.Fatal("expired result was retained, activated, or printed")
	}
}

func TestAWSNodeTokenExpirySwitchingAndStatus(t *testing.T) {
	stubNodeTokenOperations(t)
	session := NewSession(ServerInfo{APIServer: "https://api.example", IgnoreTLS: true})
	requestAWSNodeToken(session, []string{"--activate"}, io.Discard)
	session.Connection.ActiveTokenExpiresAt = time.Now().Add(-time.Minute)
	if err := runKubectlWithConfig(session.Connection, strings.NewReader(""), io.Discard, io.Discard, "get", "pods"); err == nil || !strings.Contains(err.Error(), "rerun aws-get-eks-node-token") {
		t.Fatalf("expired kubectl credential: %v", err)
	}
	if err := DoKubernetesAPIRequest(session.Connection, "GET", "/api", nil, nil); err == nil || !strings.Contains(err.Error(), "rerun aws-get-eks-node-token") {
		t.Fatalf("expired API credential: %v", err)
	}
	var out bytes.Buffer
	printAWSNodeTokenStatus(&out, session, time.Now().Add(time.Hour))
	if strings.Contains(out.String(), "k8s-aws-v1") || !strings.Contains(out.String(), "expired") {
		t.Fatalf("status exposed credential or hid expiry: %s", &out)
	}
	assignServiceAccountToConnection(ServiceAccount{Name: "sa", Token: "service-account"}, &session.Connection)
	if session.Connection.ActiveTokenKind != "" || !session.Connection.ActiveTokenExpiresAt.IsZero() {
		t.Fatal("service account inherited node expiry")
	}
	session.Connection.ActiveTokenKind, session.Connection.ActiveTokenExpiresAt = "eks-node", time.Now()
	assignAuthenticationCertificateAndKeyToConnection(ClientCertificateKeyPair{Name: "cert", CACert: "ca"}, &session.Connection)
	t.Cleanup(func() { _ = os.Remove(session.Connection.CAPath) })
	if session.Connection.ActiveTokenKind != "" || !session.Connection.ActiveTokenExpiresAt.IsZero() {
		t.Fatal("certificate inherited node expiry")
	}
}

func TestAWSMetadataCredentialRegistryStoresOnlySuccess(t *testing.T) {
	old := acquireAWSMetadataCredentials
	t.Cleanup(func() { acquireAWSMetadataCredentials = old })
	for _, success := range []bool{true, false} {
		session := NewSession(ServerInfo{})
		session.AWSCredentials.AccessKeyID = "previous"
		acquireAWSMetadataCredentials = func(bool) (AWSCredentials, error) {
			creds := AWSCredentials{AccessKeyID: "new"}
			if success {
				return creds, nil
			}
			return creds, errors.New("failure")
		}
		if _, found := newModuleRegistry(session).Run("aws-get-token"); !found {
			t.Fatal("command not registered")
		}
		want := "previous"
		if success {
			want = "new"
		}
		if session.AWSCredentials.AccessKeyID != want {
			t.Fatalf("success=%t credential=%s", success, session.AWSCredentials.AccessKeyID)
		}
	}
}

func TestCredentialDiagnosticRedaction(t *testing.T) {
	input := []string{"kubectl", "--token=secret-a", "--token", "secret-b", "-t", "secret-c", "--client-key=/secret/key", "--server=https://api", "--field-selector=secret-name", "k8s-aws-v1.secret-d"}
	got := redactCredentialArgs(input)
	for _, secret := range []string{"secret-a", "secret-b", "secret-c", "secret-d", "/secret/key"} {
		if strings.Contains(strings.Join(got, " "), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if got[7] != input[7] || got[8] != input[8] || reflect.DeepEqual(got, input) {
		t.Fatal("redaction changed unrelated arguments or mutated input")
	}
}

func TestAWSNodeTokenMainHelper(t *testing.T) {
	if os.Getenv("PEIRATES_NODE_TOKEN_HELPER") != "1" {
		return
	}
	stubNodeTokenOperations(t)
	http.DefaultTransport = nodeTokenForbiddenStartupTransport{t}
	os.Args = []string{"peirates", "-v", "-m", os.Getenv("PEIRATES_NODE_TOKEN_COMMAND")}
	Main()
}

type nodeTokenForbiddenStartupTransport struct{ t *testing.T }

func (transport nodeTokenForbiddenStartupTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.t.Fatal("node-token Main invocation made an unrelated startup request")
	return nil, errors.New("forbidden startup request")
}

func TestAWSNodeTokenCommandSurfaces(t *testing.T) {
	for _, command := range []string{"aws-get-eks-node-token", "37", "aws-get-eks-node-token --help", "37 -h", "37 --cluster-name override --region us-east-1", "aws-get-eks-node-token --verify", "aws-get-eks-node-token --check", "37 --check", "37 --activate", "37 --check --verify", "37 --check --activate", "37 --bad-option", "37 --cluster-name 'unterminated"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAWSNodeTokenMainHelper$")
			cmd.Env = append(os.Environ(), "PEIRATES_NODE_TOKEN_HELPER=1", "PEIRATES_NODE_TOKEN_COMMAND="+command, "AWS_ACCESS_KEY_ID=ambient-access-key-sentinel", "AWS_SECRET_ACCESS_KEY=ambient-secret-key-sentinel", "AWS_SESSION_TOKEN=ambient-session-token-sentinel")
			output, err := cmd.CombinedOutput()
			want := "Bearer token: k8s-aws-v1.secret"
			if strings.Contains(command, "--help") || command == "37 -h" {
				want = "Usage: aws-get-eks-node-token"
			} else if strings.Contains(command, "--bad-option") || strings.Contains(command, "unterminated") || strings.Contains(command, "--check --") {
				want = "[-] EKS node token:"
			}
			if err != nil || !strings.Contains(string(output), want) {
				t.Fatalf("-m failed or prompted: %v\n%s", err, output)
			}
			if want == "Bearer token: k8s-aws-v1.secret" {
				wantActivation := !strings.Contains(command, "--check") && !strings.Contains(command, "--verify")
				if strings.Contains(string(output), "Activated EKS node token.") != wantActivation {
					t.Fatalf("unexpected activation for %q: %s", command, output)
				}
				if strings.Contains(command, "--check") && strings.Contains(string(output), "Verified Kubernetes node identity:") {
					t.Fatal("--check verified the node identity")
				}
			}
			for _, secret := range []string{"ambient-access-key-sentinel", "ambient-secret-key-sentinel", "ambient-session-token-sentinel"} {
				if strings.Contains(string(output), secret) {
					t.Fatalf("new module printed unrelated AWS credential %s", secret)
				}
			}
		})
	}
	for _, completion := range []string{setUpCompletionMainMenu().Tree(""), ui.SetUpCompletionMainMenu().Tree("")} {
		if !strings.Contains(completion, "aws-get-eks-node-token") {
			t.Fatal("missing completion")
		}
	}
}
