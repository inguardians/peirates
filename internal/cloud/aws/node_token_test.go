package aws

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

var nodeTestNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type nodeRoundTripper func(*http.Request) (*http.Response, error)

func (f nodeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func nodeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func nodeMetadataFixture(r *http.Request) *http.Response {
	switch r.URL.Path {
	case "/latest/api/token":
		return nodeResponse(200, "imds-private-token")
	case "/latest/meta-data/iam/security-credentials/":
		return nodeResponse(200, "node-role\n")
	case "/latest/meta-data/iam/security-credentials/node-role":
		return nodeResponse(200, `{"Code":"Success","AccessKeyId":"ASIAFIXTURE","SecretAccessKey":"fixture-secret","Token":"fixture-session+/=","Expiration":"2026-10-25T13:00:00Z"}`)
	case "/latest/dynamic/instance-identity/document":
		return nodeResponse(200, `{"region":"us-west-2","instanceId":"i-1234567890abcdef0","accountId":"123456789012","availabilityZone":"different-zone"}`)
	case "/latest/meta-data/local-hostname":
		return nodeResponse(200, "ip-10-0-0-1.us-west-2.compute.internal")
	case "/latest/user-data":
		return nodeResponse(200, "#!/bin/bash\n/etc/eks/bootstrap.sh 'fallback-cluster'\n")
	}
	return nodeResponse(404, "private-response-body")
}

func fixtureNodeClient(t *testing.T, handle nodeRoundTripper) *NodeTokenClient {
	t.Helper()
	client := NewNodeTokenClient()
	client.Now = func() time.Time { return nodeTestNow }
	client.HTTPClient = &http.Client{Transport: handle}
	return client
}

func TestNodeTokenZeroArgumentProtocolAndCredentialIsolation(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT-KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "AMBIENT-SECRET")
	t.Setenv("AWS_SESSION_TOKEN", "AMBIENT-TOKEN")
	t.Setenv("AWS_REGION", "eu-west-1")
	var calls []string
	client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Host+r.URL.Path)
		if r.URL.Host == "169.254.169.254" {
			if r.URL.Path == "/latest/api/token" {
				if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "21600" {
					t.Fatal("incorrect IMDSv2 negotiation")
				}
			} else if r.Header.Get("X-aws-ec2-metadata-token") != "imds-private-token" {
				t.Fatal("missing IMDSv2 token")
			}
			return nodeMetadataFixture(r), nil
		}
		if r.URL.Host != "ec2.us-west-2.amazonaws.com" || r.Method != http.MethodPost {
			t.Fatalf("unexpected AWS request %s %s", r.Method, r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		want := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {"i-1234567890abcdef0"}}
		if !reflect.DeepEqual(values, want) {
			t.Fatalf("instance-scoped query = %v", values)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAFIXTURE/") || r.Header.Get("X-Amz-Security-Token") != "fixture-session+/=" {
			t.Fatal("AWS request did not use only metadata credentials")
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "" {
			t.Fatal("metadata token leaked to AWS API")
		}
		return nodeResponse(200, `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-1234567890abcdef0</instanceId><privateDnsName>ip-10-0-0-1.us-west-2.compute.internal</privateDnsName><tagSet><item><key>aws:eks:cluster-name</key><value>real-cluster</value></item><item><key>kubernetes.io/cluster/real-cluster</key><value>owned</value></item><item><key>Name</key><value>never-a-cluster</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`), nil
	})
	result, err := client.Generate(context.Background(), NodeTokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.ClusterName != "real-cluster" || result.Region != "us-west-2" || result.RoleIdentity != "123456789012/node-role" || result.PrivateDNSName == "" || result.Corroborated {
		t.Fatalf("incorrect provenance: cluster=%s region=%s role=%s", result.ClusterName, result.Region, result.RoleIdentity)
	}
	if len(calls) != 5 {
		t.Fatalf("unexpected request count %d: %v", len(calls), calls)
	}
	verifyNodeSignature(t, result.Token, "real-cluster", "fixture-secret", "fixture-session+/=")
	if !result.ExpiresAt.Equal(nodeTestNow.Add(14 * time.Minute)) {
		t.Fatalf("expiry = %s", result.ExpiresAt)
	}
}

// This verification intentionally implements SigV4's canonical request and HMAC
// derivation independently, rather than comparing two calls to the SDK signer.
func verifyNodeSignature(t *testing.T, token, cluster, secret, session string) {
	t.Helper()
	if !strings.HasPrefix(token, "k8s-aws-v1.") {
		t.Fatal("wrong EKS token prefix")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "k8s-aws-v1."))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(decoded))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || q.Get("Action") != "GetCallerIdentity" || q.Get("Version") != "2011-06-15" || q.Get("X-Amz-Expires") != "60" || q.Get("X-Amz-Security-Token") != session || q.Get("X-Amz-SignedHeaders") != "host;x-k8s-aws-id" {
		t.Fatal("incorrect signed EKS request fields")
	}
	signature := q.Get("X-Amz-Signature")
	q.Del("X-Amz-Signature")
	hash := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	canonical := "GET\n/\n" + strings.ReplaceAll(q.Encode(), "+", "%20") + "\nhost:" + u.Host + "\nx-k8s-aws-id:" + cluster + "\n\nhost;x-k8s-aws-id\n" + hash("")
	scope := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(scope) != 5 || scope[0] != "ASIAFIXTURE" || scope[3] != "sts" {
		t.Fatal("invalid credential scope")
	}
	stringToSign := "AWS4-HMAC-SHA256\n" + q.Get("X-Amz-Date") + "\n" + strings.Join(scope[1:], "/") + "\n" + hash(canonical)
	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(data))
		return h.Sum(nil)
	}
	key := []byte("AWS4" + secret)
	for _, component := range scope[1:] {
		key = mac(key, component)
	}
	if hex.EncodeToString(mac(key, stringToSign)) != signature {
		t.Fatal("SigV4 signature failed independent verification")
	}
}

func TestNodeTokenSigningPartitionsAndExpiry(t *testing.T) {
	creds := Credentials{AccessKeyID: "ASIAFIXTURE", SecretAccessKey: "fixture-secret", SessionToken: "fixture-session+/="}
	for _, tc := range []struct{ region, host string }{{"us-east-1", "sts.us-east-1.amazonaws.com"}, {"cn-north-1", "sts.cn-north-1.amazonaws.com.cn"}, {"us-gov-west-1", "sts.us-gov-west-1.amazonaws.com"}} {
		t.Run(tc.region, func(t *testing.T) {
			token, expiry, err := signNodeToken("cluster", tc.region, creds, nodeTestNow.Add(3*time.Minute), nodeTestNow)
			if err != nil {
				t.Fatal(err)
			}
			verifyNodeSignature(t, token, "cluster", "fixture-secret", "fixture-session+/=")
			decoded, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "k8s-aws-v1."))
			u, _ := url.Parse(string(decoded))
			if u.Host != tc.host || !expiry.Equal(nodeTestNow.Add(3*time.Minute)) {
				t.Fatalf("host/expiry: %s %s", u.Host, expiry)
			}
		})
	}
	if _, _, err := signNodeToken("cluster", "us-west-2", creds, nodeTestNow, nodeTestNow); err == nil {
		t.Fatal("expired credentials accepted")
	}
}

func TestNodeTokenFallbackAndOverrides(t *testing.T) {
	for _, status := range []int{403, 404, 405, 500, 302} {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("status%d_allow%t", status, allow), func(t *testing.T) {
				requests := 0
				client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
					requests++
					if r.URL.Path == "/latest/api/token" {
						return nodeResponse(status, "private-response-body"), nil
					}
					if r.Header.Get("X-aws-ec2-metadata-token") != "" {
						t.Fatal("IMDSv1 sent token header")
					}
					return nodeMetadataFixture(r), nil
				})
				result, err := client.Generate(context.Background(), NodeTokenOptions{AllowIMDSv1: allow, ClusterName: "override", Region: "eu-west-1"})
				wantSuccess := allow && (status == 403 || status == 404 || status == 405)
				if (err == nil) != wantSuccess {
					t.Fatalf("success = %t, want %t", err == nil, wantSuccess)
				}
				if !wantSuccess && requests != 1 {
					t.Fatal("unexpected request after failed negotiation")
				}
				if wantSuccess && (result.Region != "eu-west-1" || result.ClusterName != "override" || result.RegionSource != "--region override") {
					t.Fatal("override ignored")
				}
			})
		}
	}
}

func TestNodeTokenDiscoveryFallbackIsBoundedAndRedacted(t *testing.T) {
	for _, apiFailure := range []string{"denied", "timeout", "empty", "transport_secret"} {
		t.Run(apiFailure, func(t *testing.T) {
			awsCalls := 0
			client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "169.254.169.254" {
					return nodeMetadataFixture(r), nil
				}
				awsCalls++
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > nodeRequestTimeout {
					t.Fatal("unbounded API request")
				}
				if apiFailure == "timeout" {
					return nil, context.DeadlineExceeded
				}
				if apiFailure == "transport_secret" {
					return nil, errors.New("private AWS credential and response details")
				}
				if apiFailure == "empty" {
					return nodeResponse(200, `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-1234567890abcdef0</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`), nil
				}
				return nodeResponse(403, "private AWS credential and response details"), nil
			})
			result, err := client.Generate(context.Background(), NodeTokenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if result.ClusterName != "fallback-cluster" || awsCalls != 1 {
				t.Fatal("fallback or retry bound failed")
			}
			if strings.Contains(strings.Join(result.Diagnostics, " "), "private") {
				t.Fatal("private error details leaked")
			}
			if apiFailure == "denied" && !strings.Contains(strings.Join(result.Diagnostics, " "), "HTTP 403") {
				t.Fatal("missing sanitized denial status")
			}
			if apiFailure == "timeout" && !strings.Contains(strings.Join(result.Diagnostics, " "), "timed out") {
				t.Fatal("missing sanitized timeout reason")
			}
		})
	}
}

func TestNodeTokenInvalidMetadataAndRedaction(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"empty_token", "/latest/api/token", ""},
		{"ambiguous_role", "/latest/meta-data/iam/security-credentials/", "role1\nrole2"},
		{"role_path", "/latest/meta-data/iam/security-credentials/", "../../secret"},
		{"bad_credentials", "/latest/meta-data/iam/security-credentials/node-role", `{"Code":"Success","AccessKeyId":"PRIVATE-KEY"}`},
		{"bad_json", "/latest/meta-data/iam/security-credentials/node-role", `{"Token":"PRIVATE-KEY"`},
		{"expired", "/latest/meta-data/iam/security-credentials/node-role", `{"Code":"Success","AccessKeyId":"PRIVATE-KEY","SecretAccessKey":"secret","Token":"session","Expiration":"2020-01-01T00:00:00Z"}`},
		{"identity_account", "/latest/dynamic/instance-identity/document", `{"region":"us-west-2","instanceId":"i-12345678","accountId":"PRIVATE-KEY"}`},
		{"identity_region", "/latest/dynamic/instance-identity/document", `{"region":"PRIVATE-KEY","instanceId":"i-12345678","accountId":"123456789012"}`},
		{"too_large", "/latest/api/token", strings.Repeat("X", nodeResponseLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == tc.path {
					return nodeResponse(200, tc.body), nil
				}
				return nodeMetadataFixture(r), nil
			})
			result, err := client.Generate(context.Background(), NodeTokenOptions{ClusterName: "cluster"})
			if err == nil || result.Token != "" {
				t.Fatal("invalid metadata accepted")
			}
			if strings.Contains(err.Error(), "PRIVATE-KEY") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestNodeTokenTransportSafety(t *testing.T) {
	client := NewNodeTokenClient()
	transport := client.HTTPClient.Transport.(*http.Transport)
	if transport.Proxy != nil || client.HTTPClient.Timeout != 5*time.Second {
		t.Fatal("metadata transport is not bounded and proxy-free")
	}
	if err := client.HTTPClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("redirect policy unsafe")
	}
	requests := 0
	client = fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		response := nodeResponse(302, "")
		response.Header.Set("Location", "https://untrusted.example/credentials")
		return response, nil
	})
	if _, err := client.Generate(context.Background(), NodeTokenOptions{AllowIMDSv1: true}); err == nil || requests != 1 {
		t.Fatal("redirect was followed or downgraded")
	}
	client = fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := client.Generate(ctx, NodeTokenOptions{AllowIMDSv1: true}); err == nil {
		t.Fatal("timeout was ignored")
	}
}

type fakeNodeDiscovery struct {
	instance InstanceDescription
	clusters map[string]ClusterDescription
	calls    []string
}

func (d *fakeNodeDiscovery) DescribeInstance(context.Context, string, string, Credentials) (InstanceDescription, error) {
	return d.instance, nil
}
func (d *fakeNodeDiscovery) DescribeCluster(_ context.Context, _, name string, _ Credentials) (ClusterDescription, error) {
	d.calls = append(d.calls, name)
	if cluster, ok := d.clusters[name]; ok {
		return cluster, nil
	}
	return ClusterDescription{}, errors.New("unavailable")
}

func nodeTestCA(t *testing.T, serial int64) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: nodeTestNow, NotAfter: nodeTestNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestNodeTokenClusterCorroboration(t *testing.T) {
	trusted, other := nodeTestCA(t, 1), nodeTestCA(t, 2)
	for _, tc := range []struct {
		name         string
		candidates   map[string]string
		ca           []byte
		endpoint     string
		descriptions map[string]ClusterDescription
		want         string
		corroborated bool
		wantError    bool
	}{
		{"unique_unavailable", map[string]string{"a": "tags"}, trusted, "", nil, "a", false, false},
		{"unique_match", map[string]string{"a": "tags"}, trusted, "https://10.96.0.1", map[string]ClusterDescription{"a": {Name: "a", CA: trusted, Endpoint: "https://real.eks.amazonaws.com"}}, "a", true, false},
		{"unique_mismatch", map[string]string{"a": "tags"}, trusted, "", map[string]ClusterDescription{"a": {Name: "a", CA: other}}, "", false, true},
		{"hostname_mismatch", map[string]string{"a": "override"}, trusted, "https://wrong.eks.amazonaws.com", map[string]ClusterDescription{"a": {Name: "a", CA: trusted, Endpoint: "https://real.eks.amazonaws.com"}}, "", false, true},
		{"ambiguous_match", map[string]string{"a": "tags", "b": "tags"}, trusted, "", map[string]ClusterDescription{"a": {Name: "a", CA: other}, "b": {Name: "b", CA: trusted}}, "b", true, false},
		{"ambiguous_same_ca", map[string]string{"a": "tags", "b": "tags"}, trusted, "", map[string]ClusterDescription{"a": {Name: "a", CA: trusted}, "b": {Name: "b", CA: trusted}}, "", false, true},
		{"ambiguous_no_trust", map[string]string{"a": "tags", "b": "tags"}, nil, "", nil, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeNodeDiscovery{clusters: tc.descriptions}
			name, corroborated, err := resolveNodeCluster(context.Background(), d, tc.candidates, "us-west-2", Credentials{}, NodeTokenOptions{TrustedCA: tc.ca, APIEndpoint: tc.endpoint})
			if (err != nil) != tc.wantError || name != tc.want || corroborated != tc.corroborated {
				t.Fatalf("resolution = %q %t %v", name, corroborated, err)
			}
		})
	}
}

func TestNodeTokenCandidateLimitAndInvalidOverrides(t *testing.T) {
	d := &fakeNodeDiscovery{instance: InstanceDescription{InstanceID: "i-1234567890abcdef0", Tags: map[string]string{}}}
	for i := 0; i < 9; i++ {
		d.instance.Tags[fmt.Sprintf("kubernetes.io/cluster/cluster%d", i)] = "owned"
	}
	client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) { return nodeMetadataFixture(r), nil })
	client.Discovery = d
	if _, err := client.Generate(context.Background(), NodeTokenOptions{}); err == nil || len(d.calls) != 0 {
		t.Fatal("candidate limit not enforced before EKS calls")
	}
	client = fixtureNodeClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid override performed a request")
		return nil, nil
	})
	for _, options := range []NodeTokenOptions{{ClusterName: "../private"}, {Region: "us-west-2.attacker"}} {
		if _, err := client.Generate(context.Background(), options); err == nil {
			t.Fatal("invalid override accepted")
		}
	}
}

func TestNodeDiscoveryEKSResponse(t *testing.T) {
	ca := nodeTestCA(t, 1)
	client := fixtureNodeClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://eks.us-west-2.amazonaws.com/clusters/cluster" || r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Authorization"), "/eks/aws4_request") {
			t.Fatal("incorrect EKS request")
		}
		body, _ := json.Marshal(map[string]any{"cluster": map[string]any{"name": "cluster", "endpoint": "https://cluster.eks.amazonaws.com", "certificateAuthority": map[string]string{"data": base64.StdEncoding.EncodeToString(ca)}}})
		return nodeResponse(200, string(body)), nil
	})
	api := &nodeAWSAPI{client: client.HTTPClient, now: client.Now}
	result, err := api.DescribeCluster(context.Background(), "us-west-2", "cluster", Credentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "session"})
	if err != nil || string(result.CA) != string(ca) {
		t.Fatalf("cluster response: %v", err)
	}
}
