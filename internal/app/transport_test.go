package app

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	cert := server.Certificate()
	if cert == nil {
		t.Fatal("TLS test server did not provide a certificate")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}
	return path
}

func TestDoHTTPRequestAndGetBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failure" {
			http.Error(w, "nope", http.StatusTeapot)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/success", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := DoHTTPRequestAndGetBody(req, false, false, "")
	if err != nil || string(body) != "ok" {
		t.Fatalf("got body %q, error %v", body, err)
	}

	req, err = http.NewRequest(http.MethodGet, server.URL+"/failure", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DoHTTPRequestAndGetBody(req, false, false, ""); err == nil {
		t.Fatal("expected non-2xx response to fail")
	}
}

func TestDoHTTPRequestAndGetBodyTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	defer server.Close()

	for name, test := range map[string]struct {
		caPath   string
		insecure bool
	}{
		"custom CA":         {writeServerCA(t, server), false},
		"ignore TLS errors": {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := DoHTTPRequestAndGetBody(req, true, test.insecure, test.caPath)
			if err != nil || string(body) != "secure" {
				t.Fatalf("got body %q, error %v", body, err)
			}
		})
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	if _, err := DoHTTPRequestAndGetBody(req, true, false, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("expected missing CA file to fail")
	}
}

func TestGetRequestAndCreateHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "value" {
			t.Errorf("missing custom header")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer server.Close()

	body, status, err := GetRequest(server.URL, []HeaderLine{{LHS: "X-Test", RHS: "value"}}, false)
	if err != nil || status != http.StatusCreated || body != "created" {
		t.Fatalf("got (%q, %d, %v)", body, status, err)
	}

	req, err := createHTTPrequest(http.MethodPost, server.URL, nil, "body", map[string]string{"a": "hello world", "b": "2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", got)
	}
	data, _ := io.ReadAll(req.Body)
	values, err := url.ParseQuery(string(data))
	if err != nil || values.Get("a") != "hello world" || values.Get("b") != "2" {
		t.Fatalf("form body %q, parse error %v", data, err)
	}

	req, err = createHTTPrequest(http.MethodGet, server.URL, nil, "url", map[string]string{"x": "one", "y": "two"})
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("x") != "one" || req.URL.Query().Get("y") != "two" {
		t.Fatalf("query = %q", req.URL.RawQuery)
	}

	req, err = createHTTPrequest(http.MethodPost, server.URL, []HeaderLine{{LHS: "Content-Type", RHS: "text/plain"}}, "body", map[string]string{"x": "value"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(req.Body)
	if string(data) != "xvalue\n" {
		t.Fatalf("non-form body = %q", data)
	}

	req, err = createHTTPrequest(http.MethodGet, server.URL, nil, "invalid", map[string]string{"x": "value"})
	if err != nil || req != nil {
		t.Fatalf("invalid location got request %v, error %v", req, err)
	}
}

func TestCurlNonWizard(t *testing.T) {
	req, https, insecure, caPath, err := curlNonWizard("-X", "POST", "-k", "-d", "name=Jane Doe", "https://example.test/api")
	if err != nil || !https || !insecure || caPath != "" {
		t.Fatalf("unexpected curl result: https=%t insecure=%t ca=%q err=%v", https, insecure, caPath, err)
	}
	if req.Method != http.MethodPost || req.URL.String() != "https://example.test/api" {
		t.Fatalf("request = %s %s", req.Method, req.URL)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "name=Jane%2BDoe" {
		t.Fatalf("body = %q", body)
	}

	if _, _, _, _, err := curlNonWizard("-d", "invalid", "http://example.test"); err == nil {
		t.Fatal("expected invalid data argument to fail")
	}
}

func TestIPAddressHelpers(t *testing.T) {
	if _, err := GetMyIPAddress("peirates-interface-that-does-not-exist"); err == nil {
		t.Fatal("expected unknown interface to fail")
	}
	for _, address := range GetMyIPAddressesNative() {
		if address == "127.0.0.1" || net.ParseIP(address) == nil {
			t.Fatalf("unexpected address %q", address)
		}
	}
}

func TestDoKubernetesAPIRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apis/test" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		var query map[string]string
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil || query["name"] != "value" {
			t.Errorf("query = %#v, error = %v", query, err)
		}
		_, _ = io.WriteString(w, `{"answer":"yes"}`)
	}))
	defer server.Close()

	cfg := ServerInfo{APIServer: server.URL, Token: "token", CAPath: writeServerCA(t, server)}
	var response struct {
		Answer string `json:"answer"`
	}
	if err := DoKubernetesAPIRequest(cfg, http.MethodPost, "/apis/test", map[string]string{"name": "value"}, &response); err != nil || response.Answer != "yes" {
		t.Fatalf("response %#v, error %v", response, err)
	}
	if err := DoKubernetesAPIRequest(cfg, http.MethodPost, "apis/test", func() {}, &response); err == nil {
		t.Fatal("expected unmarshalable request query to fail")
	}
	cfg.CAPath = ""
	cfg.IgnoreTLS = true
	if err := DoKubernetesAPIRequest(cfg, http.MethodPost, "apis/test", map[string]string{"name": "value"}, &response); err != nil || response.Answer != "yes" {
		t.Fatalf("insecure response %#v, error %v", response, err)
	}
}

func TestNewKubeRequest(t *testing.T) {
	request, err := newKubeRequest("api/v1/pods", RequestConfig{Host: "127.0.0.1", Port: 8443, Method: http.MethodGet, HTTPS: true})
	if err != nil || request.URL.String() != "https://127.0.0.1:8443/api/v1/pods" {
		t.Fatalf("request %v, error %v", request.URL, err)
	}
	request, err = newKubeRequest("healthz", RequestConfig{Host: "localhost", Port: 8080, Method: http.MethodHead})
	if err != nil || request.URL.String() != "http://localhost:8080/healthz" {
		t.Fatalf("request %v, error %v", request.URL, err)
	}
}

func TestKubectlWrapperValidationAndAccountFallback(t *testing.T) {
	var stdout, stderr strings.Builder
	if err := runKubectlWithConfig(ServerInfo{}, strings.NewReader(""), &stdout, &stderr, "get", "pods"); err == nil || err.Error() != "api server not set" {
		t.Fatalf("unexpected missing API server error: %v", err)
	}
	if err := runKubectlWithConfig(ServerInfo{APIServer: "https://example.test"}, strings.NewReader(""), &stdout, &stderr, "get", "pods"); err == nil || !strings.Contains(err.Error(), "certificate authority") {
		t.Fatalf("unexpected missing CA error: %v", err)
	}

	cfg := ServerInfo{APIServer: "https://example.test", Token: "original"}
	accounts := []ServiceAccount{}
	certificates := []ClientCertificateKeyPair{}
	if _, _, err := attemptEveryAccount(false, &cfg, &accounts, &certificates, false, "", "get", "pods"); err == nil || err.Error() != "no principals worked" {
		t.Fatalf("unexpected account fallback error: %v", err)
	}
	if cfg.Token != "original" {
		t.Fatalf("configuration was not restored: %#v", cfg)
	}
}

func TestKubectlAuthCanI(t *testing.T) {
	cfg := ServerInfo{UseAuthCanI: false}
	if !kubectlAuthCanI(cfg, "get", "pods") {
		t.Fatal("disabled auth check should allow request")
	}
	cfg = ServerInfo{UseAuthCanI: true, ClientCertData: "cert"}
	if !kubectlAuthCanI(cfg, "get", "pods") {
		t.Fatal("certificate auth is currently allowed without an API check")
	}
	if kubectlAuthCanI(ServerInfo{APIServer: "https://127.0.0.1:1", UseAuthCanI: true}, "get", "pods") {
		t.Fatal("failed API request should deny request")
	}
}

func TestWriteServerCAProducesParseableCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	data, err := os.ReadFile(writeServerCA(t, server))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
}
