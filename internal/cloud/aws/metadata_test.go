package aws

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialsFromEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")
	got := CredentialsFromEnvironment()
	if got.AccessKeyID != "key" || got.SecretAccessKey != "secret" || got.SessionToken != "token" {
		t.Fatalf("credentials = %#v", got)
	}
}

func TestMetadataCredentialsV1AndRegion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte("role"))
		case "/latest/meta-data/iam/security-credentials/role":
			_, _ = w.Write([]byte(`{"AccessKeyId":"key","SecretAccessKey":"secret","Token":"token"}`))
		case "/latest/meta-data/placement/availability-zone":
			_, _ = w.Write([]byte("us-west-2b"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := MetadataClient{BaseURL: server.URL, Client: server.Client()}
	credentials, err := client.CredentialsV1()
	if err != nil || credentials.AccessKeyID != "key" || credentials.AccountName != "role" {
		t.Fatalf("CredentialsV1() = %#v, %v", credentials, err)
	}
	region, zone, err := client.RegionAndZone()
	if err != nil || region != "us-west-2" || zone != "us-west-2b" {
		t.Fatalf("RegionAndZone() = %q, %q, %v", region, zone, err)
	}
}

func TestMetadataCredentialsV2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest/api/token" && r.Header.Get("X-aws-ec2-metadata-token") != "token" {
			t.Fatalf("token header = %q", r.Header.Get("X-aws-ec2-metadata-token"))
		}
		switch r.URL.Path {
		case "/latest/api/token":
			if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "21600" {
				t.Fatalf("token request = %#v", r)
			}
			_, _ = w.Write([]byte("token"))
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte("role"))
		case "/latest/meta-data/iam/security-credentials/role":
			_, _ = w.Write([]byte(`{"AccessKeyId":"key","Token":"session"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credentials, err := (MetadataClient{BaseURL: server.URL, Client: server.Client()}).CredentialsV2()
	if err != nil || credentials.AccessKeyID != "key" || credentials.SessionToken != "session" {
		t.Fatalf("CredentialsV2() = %#v, %v", credentials, err)
	}
}
