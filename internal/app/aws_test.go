package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func useAWSMetadataServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	oldBaseURL, oldClient := awsMetadataBaseURL, awsHTTPClient
	awsMetadataBaseURL, awsHTTPClient = server.URL, server.Client()
	t.Cleanup(func() {
		awsMetadataBaseURL, awsHTTPClient = oldBaseURL, oldClient
	})
}

func TestValidateAWSInput(t *testing.T) {
	tests := []struct {
		name      string
		component string
		pattern   string
		input     string
		wantErr   bool
	}{
		{name: "valid access key", component: "AccessKeyId", pattern: `\w{18,}`, input: "ABCDEFGHIJKLMNOPQR"},
		{name: "short access key", component: "AccessKeyId", pattern: `\w{18,}`, input: "short", wantErr: true},
		{name: "valid secret key", component: "SecretAccessKey", pattern: `\w{18,}`, input: "abcdefghijklmnopqr"},
		{name: "short secret key", component: "SecretAccessKey", pattern: `\w{18,}`, input: "short", wantErr: true},
		{name: "valid session token", component: "session token", pattern: `\w{5,}`, input: "abcde"},
		{name: "short session token", component: "session token", pattern: `\w{5,}`, input: "abcd", wantErr: true},
		{name: "valid account name", component: "name or comment", pattern: `\w{1,}`, input: "account"},
		{name: "account name without word characters", component: "name or comment", pattern: `\w{1,}`, input: "---", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAWSInput(tt.component, tt.pattern, tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAWSInput(%q, %q, %q) error = %v, wantErr %v", tt.component, tt.pattern, tt.input, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.component) {
				t.Fatalf("error %q does not identify component %q", err, tt.component)
			}
		})
	}
}

func TestValidateAWSInputRejectsInvalidPattern(t *testing.T) {
	err := validateAWSInput("component", `[`, "value")
	if err == nil || !strings.Contains(err.Error(), "validate component") {
		t.Fatalf("validateAWSInput() error = %v", err)
	}
}

func TestPullIamCredentialsFromEnvironmentVariables(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")

	got := PullIamCredentialsFromEnvironmentVariables()
	if got.AccessKeyID != "key" || got.SecretAccessKey != "secret" || got.SessionToken != "token" {
		t.Fatalf("credentials = %#v", got)
	}
	if got.accountName != "AWS Credentials from Environment Variables" {
		t.Fatalf("account name = %q", got.accountName)
	}
}

func TestPullIamCredentialsFromAWS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte("role-name"))
		case "/latest/meta-data/iam/security-credentials/role-name":
			_, _ = w.Write([]byte(`{"AccessKeyId":"key","SecretAccessKey":"secret","Token":"token"}`))
		default:
			t.Errorf("unexpected metadata path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	got, err := PullIamCredentialsFromAWS()
	if err != nil {
		t.Fatalf("PullIamCredentialsFromAWS() error = %v", err)
	}
	if got.AccessKeyID != "key" || got.SecretAccessKey != "secret" || got.SessionToken != "token" || got.accountName != "role-name" {
		t.Fatalf("credentials = %#v", got)
	}
}

func TestPullIamCredentialsFromAWSRejectsFailedRoleRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	if _, err := PullIamCredentialsFromAWS(); err == nil {
		t.Fatal("PullIamCredentialsFromAWS() succeeded for failed response")
	}
}

func TestRequestAWSIMDSv2Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/latest/api/token" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"); got != "21600" {
			t.Fatalf("TTL header = %q", got)
		}
		_, _ = w.Write([]byte("metadata-token"))
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	got, err := RequestAWSIMDSv2Token()
	if err != nil || got != "metadata-token" {
		t.Fatalf("RequestAWSIMDSv2Token() = %q, %v", got, err)
	}
}

func TestRequestAWSIMDSv2TokenRejectsNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	if _, err := RequestAWSIMDSv2Token(); err == nil {
		t.Fatal("RequestAWSIMDSv2Token() succeeded for forbidden response")
	}
}

func TestPullIamCredentialsFromAWSWithIMDSv2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest/api/token" && r.Header.Get("X-aws-ec2-metadata-token") != "token" {
			t.Fatalf("metadata token header = %q", r.Header.Get("X-aws-ec2-metadata-token"))
		}
		switch r.URL.Path {
		case "/latest/api/token":
			_, _ = w.Write([]byte("token"))
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte("role"))
		case "/latest/meta-data/iam/security-credentials/role":
			_, _ = w.Write([]byte(`{"AccessKeyId":"key","SecretAccessKey":"secret","Token":"session"}`))
		}
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	got, err := PullIamCredentialsFromAWSWithIMDSv2()
	if err != nil || got.AccessKeyID != "key" || got.SessionToken != "session" {
		t.Fatalf("PullIamCredentialsFromAWSWithIMDSv2() = %#v, %v", got, err)
	}
}

func TestGetAWSRegionAndZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("us-west-2b"))
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	region, zone, err := GetAWSRegionAndZone()
	if err != nil || region != "us-west-2" || zone != "us-west-2b" {
		t.Fatalf("GetAWSRegionAndZone() = %q, %q, %v", region, zone, err)
	}
}

func TestGetAWSRegionAndZoneRejectsShortZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	if _, _, err := GetAWSRegionAndZone(); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("GetAWSRegionAndZone() error = %v", err)
	}
}

func TestGetAWSRegionAndZoneUsesIMDSv2AfterIMDSv1Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/placement/availability-zone":
			if r.Header.Get("X-aws-ec2-metadata-token") == "token" {
				_, _ = w.Write([]byte("eu-central-1a"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/latest/api/token":
			_, _ = w.Write([]byte("token"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	useAWSMetadataServer(t, server)

	region, zone, err := GetAWSRegionAndZone()
	if err != nil || region != "eu-central-1" || zone != "eu-central-1a" {
		t.Fatalf("GetAWSRegionAndZone() = %q, %q, %v", region, zone, err)
	}
}

func TestAWSSTSAssumeRoleRejectsInvalidARN(t *testing.T) {
	input := AWSCredentials{AccessKeyID: "key"}
	got, err := AWSSTSAssumeRole(input, "not-an-arn")
	if err == nil || !strings.Contains(err.Error(), "invalid role") || got.AccessKeyID != "" {
		t.Fatalf("AWSSTSAssumeRole() = %#v, %v", got, err)
	}
}
