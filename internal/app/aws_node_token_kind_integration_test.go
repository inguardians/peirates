//go:build aws_node_kind

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awscloud "github.com/inguardians/peirates/internal/cloud/aws"
	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
)

// These credentials exist only in the fixture webhook; they are not AWS keys.
const kindAWSAccess = "AKIDPEIRATESKINDTEST"
const kindAWSSecret = "peirates-kind-fixture-secret-not-an-aws-credential"
const kindAWSSession = "peirates-kind-fixture-session"

type kindAWSDiscovery struct {
	t              *testing.T
	node, endpoint string
	ca             []byte
}

func (d kindAWSDiscovery) DescribeInstance(_ context.Context, region, id string, credentials awscloud.Credentials) (awscloud.InstanceDescription, error) {
	d.t.Helper()
	if region != "us-west-2" || id != "i-0123456789abcdef0" || credentials.AccessKeyID != kindAWSAccess || credentials.SecretAccessKey != kindAWSSecret || credentials.SessionToken != kindAWSSession {
		d.t.Fatal("instance lookup used unexpected scope or credentials")
	}
	return awscloud.InstanceDescription{InstanceID: id, PrivateDNSName: d.node, Tags: map[string]string{"aws:eks:cluster-name": "fixture-cluster"}}, nil
}
func (d kindAWSDiscovery) DescribeCluster(_ context.Context, region, name string, _ awscloud.Credentials) (awscloud.ClusterDescription, error) {
	return awscloud.ClusterDescription{Name: name, Endpoint: d.endpoint, CA: d.ca}, nil
}

func TestAWSNodeTokenKind(t *testing.T) {
	mustEnv := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s must be supplied by test/aws-node-token-kind-integration.sh", name)
		}
		return value
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(mustEnv(name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	endpoint, node := mustEnv("PEIRATES_AWS_KIND_API_SERVER"), mustEnv("PEIRATES_AWS_KIND_NODE")
	ca, cert, key := read("PEIRATES_AWS_KIND_CA"), read("PEIRATES_AWS_KIND_CERT"), read("PEIRATES_AWS_KIND_KEY")
	// Set tempting ambient credentials to prove the dedicated metadata path wins.
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-must-not-be-used")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-must-not-be-used")
	t.Setenv("AWS_SESSION_TOKEN", "ambient-must-not-be-used")
	var broken atomic.Bool
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			http.Error(w, "fixture unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/latest/api/token" {
			if r.Method != http.MethodPut {
				t.Error("IMDSv2 request was not PUT")
			}
			_, _ = io.WriteString(w, "kind-imds-v2")
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "kind-imds-v2" {
			t.Error("metadata request omitted IMDSv2 token")
			http.Error(w, "missing token", 401)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, "fixture-node-role")
		case "/latest/meta-data/iam/security-credentials/fixture-node-role":
			_ = json.NewEncoder(w).Encode(map[string]string{"Code": "Success", "AccessKeyId": kindAWSAccess, "SecretAccessKey": kindAWSSecret, "Token": kindAWSSession, "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case "/latest/dynamic/instance-identity/document":
			_ = json.NewEncoder(w).Encode(map[string]string{"region": "us-west-2", "instanceId": "i-0123456789abcdef0", "accountId": "123456789012"})
		case "/latest/meta-data/local-hostname":
			_, _ = io.WriteString(w, node)
		default:
			http.NotFound(w, r)
		}
	}))
	defer metadata.Close()
	provider := awscloud.NewNodeTokenClient()
	provider.MetadataBaseURL, provider.HTTPClient = metadata.URL, metadata.Client()
	provider.Discovery = kindAWSDiscovery{t, node, endpoint, ca}
	oldGenerator := generateAWSNodeToken
	generateAWSNodeToken = provider.Generate
	t.Cleanup(func() { generateAWSNodeToken = oldGenerator })
	original := model.ServerInfo{APIServer: endpoint, CACertData: string(ca), ClientCertData: string(cert), ClientKeyData: string(key), ClientCertName: "competing-admin", Namespace: "default", Token: "competing-invalid-bearer"}
	session := NewSession(original)
	original = session.Connection
	session.AssumedAWSRole = AWSCredentials{AccessKeyID: "assumed-must-not-be-used"}
	var output bytes.Buffer
	requestAWSNodeToken(session, []string{"--check"}, &output)
	if len(session.AWSNodeTokens) != 1 || !reflect.DeepEqual(original, session.Connection) {
		t.Fatal("--check discovery did not retain one token and preserve connection")
	}
	var generated model.AWSNodeToken
	for _, entry := range session.AWSNodeTokens {
		generated = entry
	}
	if generated.ClusterName != "fixture-cluster" || generated.Region != "us-west-2" || generated.Verified {
		t.Fatal("automatic discovery or initial verification state was incorrect")
	}

	// Use an independent TLS HTTP client with only the generated token. No
	// Peirates Kubernetes helpers or administrative kubeconfig participate.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture API CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	independent := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	whoami := func(token string) (string, []string, int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint+"/apis/authentication.k8s.io/v1/selfsubjectreviews", strings.NewReader(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := independent.Do(req)
		if err != nil {
			t.Fatal("independent identity request failed")
		}
		defer resp.Body.Close()
		var result struct {
			Status struct {
				UserInfo struct {
					Username string   `json:"username"`
					Groups   []string `json:"groups"`
				} `json:"userInfo"`
			} `json:"status"`
		}
		if resp.StatusCode == http.StatusCreated {
			if json.NewDecoder(resp.Body).Decode(&result) != nil {
				t.Fatal("invalid independent identity response")
			}
		}
		return result.Status.UserInfo.Username, result.Status.UserInfo.Groups, resp.StatusCode
	}
	username, groups, status := whoami(generated.Token)
	if status != 201 || username != "system:node:"+node || !containsString(groups, "system:nodes") {
		t.Fatalf("independent identity mismatch: status=%d username=%q groups=%q", status, username, groups)
	}
	_, _, status = whoami(generated.Token + "tampered")
	if status != 401 && status != 403 {
		t.Fatalf("tampered token unexpectedly accepted: HTTP %d", status)
	}

	output.Reset()
	requestAWSNodeToken(session, []string{"--verify"}, &output)
	if !reflect.DeepEqual(original, session.Connection) {
		t.Fatal("verification changed the active connection")
	}
	for _, entry := range session.AWSNodeTokens {
		if !entry.Verified || !entry.InstanceMatched || entry.Username != username {
			t.Fatal("verification did not prove the fixture node identity")
		}
	}
	output.Reset()
	requestAWSNodeToken(session, nil, &output)
	active := session.Connection
	if active.Token == "" || active.ClientCertData != "" || active.ClientKeyData != "" || active.ClientCertName != "" || active.APIServer != original.APIServer || active.CACertData != original.CACertData || active.Namespace != original.Namespace || active.ActiveTokenKind != "eks-node" {
		t.Fatal("activation did not isolate node credentials while retaining target and namespace")
	}
	username, _, status = whoami(active.Token)
	if status != 201 || username != "system:node:"+node {
		t.Fatal("activated token failed independent live identity check")
	}

	// Restore real admin certificate material as a competing credential: wrong
	// cluster verification must still fail and preserve the full prior state.
	session.Connection = original
	output.Reset()
	requestAWSNodeToken(session, []string{"--cluster-name", "wrong-cluster"}, &output)
	if !reflect.DeepEqual(original, session.Connection) {
		t.Fatal("wrong-cluster activation changed the original admin connection")
	}
	var wrong model.AWSNodeToken
	for k, entry := range session.AWSNodeTokens {
		if k.ClusterName == "wrong-cluster" {
			wrong = entry
		}
	}
	if wrong.Token == "" || wrong.Verified || wrong.VerificationError == "" {
		t.Fatal("wrong-cluster rejection was not retained as unverified")
	}
	_, _, status = whoami(wrong.Token)
	if status != 401 && status != 403 {
		t.Fatal("independent wrong-cluster control unexpectedly authenticated")
	}

	// Exercise the actual temporary-kubeconfig kubectl path. The shell leaves
	// its admin KUBECONFIG in the environment deliberately; the supplied node
	// credential must be the only identity used by the subprocess.
	kubectlClient := kube.NewClient()
	kubectlClient.RunCommand = func(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "kubectl", args...)
		command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
		return command.Run()
	}
	var kubectlOutput, kubectlError bytes.Buffer
	if err := kubectlClient.RunWithConfig(active, nil, &kubectlOutput, &kubectlError, "get", "node", node, "-o", "name"); err != nil || strings.TrimSpace(kubectlOutput.String()) != "node/"+node {
		t.Fatal("activated token kubectl path failed to read its own node")
	}
	wrongActive := active
	wrongActive.Token = wrong.Token
	wrongActive.ClientCertData, wrongActive.ClientKeyData = original.ClientCertData, original.ClientKeyData
	kubectlOutput.Reset()
	kubectlError.Reset()
	if err := kubectlClient.RunWithConfig(wrongActive, nil, &kubectlOutput, &kubectlError, "get", "node", node, "-o", "name"); err == nil {
		t.Fatal("wrong-cluster kubectl unexpectedly used competing admin credentials")
	}
	if !strings.Contains(kubectlError.String(), "Unauthorized") && !strings.Contains(kubectlError.String(), "provide credentials") && !strings.Contains(kubectlError.String(), "logged in") {
		t.Fatal("wrong-cluster kubectl failed for a reason other than credential rejection")
	}

	retained := make(map[model.AWSNodeTokenKey]model.AWSNodeToken, len(session.AWSNodeTokens))
	for key, entry := range session.AWSNodeTokens {
		retained[key] = entry
	}
	broken.Store(true)
	output.Reset()
	requestAWSNodeToken(session, nil, &output)
	if !reflect.DeepEqual(session.AWSNodeTokens, retained) || !reflect.DeepEqual(original, session.Connection) {
		t.Fatal("metadata failure changed retained tokens or active identity")
	}
	if strings.Contains(output.String(), kindAWSSecret) || strings.Contains(output.String(), kindAWSSession) {
		t.Fatal("metadata diagnostics leaked fixture secrets")
	}

	// Expiration must stop API use locally; no fallback to the admin certificate.
	expired := active
	expired.ActiveTokenExpiresAt = time.Now().Add(-time.Minute)
	var ignored any
	if err := kube.DoAPIRequest(expired, "GET", "api/v1/nodes", nil, &ignored); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("expired generated token was not rejected")
	}
	kube.AssignServiceAccount(model.ServiceAccount{Name: "replacement", Token: "replacement"}, &expired)
	if expired.ActiveTokenKind != "" || !expired.ActiveTokenExpiresAt.IsZero() {
		t.Fatal("switching away left generated-token expiry metadata")
	}
	t.Log("independent live SSR, signature rejection, discovery, activation, credential isolation, failure preservation and expiry passed")
}
