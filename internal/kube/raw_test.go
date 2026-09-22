package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func defaultRawOptions(apiPath string) RawRequestOptions {
	return RawRequestOptions{
		Method:            http.MethodGet,
		APIPath:           apiPath,
		Timeout:           DefaultRawRequestTimeout,
		MaxResponseBytes:  DefaultRawResponseLimit,
		MaxErrorBodyBytes: DefaultRawErrorBodyLimit,
	}
}

func certificatePEM(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
}

func TestRawRequestBearerBytesAndNodeProxyPath(t *testing.T) {
	logPath, err := NodeProxyLogPath("worker node", "pods", "link/name?value")
	if err != nil {
		t.Fatal(err)
	}
	wantPath := "/cluster/base/api/v1/nodes/worker%20node/proxy/logs/pods/link%2Fname%3Fvalue"
	wantBody := []byte{'a', 0, 'b', 0xff}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q", request.Method)
		}
		if request.RequestURI != wantPath {
			t.Errorf("request URI = %q, want %q", request.RequestURI, wantPath)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-token" {
			t.Errorf("authorization = %q", authorization)
		}
		_, _ = writer.Write(wantBody)
	}))
	defer server.Close()

	body, err := RawRequest(context.Background(), ServerInfo{
		APIServer: server.URL + "/cluster/base",
		Token:     "test-token",
	}, defaultRawOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(wantBody) {
		t.Fatalf("body = %v, want %v", body, wantBody)
	}
}

func TestNodeProxyLogPath(t *testing.T) {
	path, err := NodeProxyLogPath("node/name", "pods and containers", "link#1")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/api/v1/nodes/node%2Fname/proxy/logs/pods%20and%20containers/link%231"; path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	probePath, err := NodeProxyLogPath("node")
	if err != nil || probePath != "/api/v1/nodes/node/proxy/logs/" {
		t.Fatalf("probe path = %q, %v", probePath, err)
	}
	for _, invalid := range []struct {
		node       string
		components []string
	}{
		{node: ""},
		{node: ".."},
		{node: "node", components: []string{""}},
		{node: "node", components: []string{"."}},
	} {
		if _, err := NodeProxyLogPath(invalid.node, invalid.components...); err == nil {
			t.Fatalf("NodeProxyLogPath(%q, %#v) unexpectedly succeeded", invalid.node, invalid.components)
		}
	}
}

func TestRawRequestRejectsOriginAndBasePathEscape(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		apiPath string
	}{
		{name: "absolute URL", server: "https://api.example/base", apiPath: "https://evil.example/path"},
		{name: "network path", server: "https://api.example/base", apiPath: "//evil.example/path"},
		{name: "plain dot segment", server: "https://api.example/base", apiPath: "/../path"},
		{name: "escaped dot segment", server: "https://api.example/base", apiPath: "/%2e%2e/path"},
		{name: "query", server: "https://api.example/base", apiPath: "/path?redirect=https://evil.example"},
		{name: "base dot segment", server: "https://api.example/base/../escape", apiPath: "/path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RawRequest(context.Background(), ServerInfo{APIServer: test.server, IgnoreTLS: true}, defaultRawOptions(test.apiPath))
			if err == nil {
				t.Fatal("request unexpectedly succeeded")
			}
		})
	}
}

func TestRawRequestTLSVerificationModes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	caData := certificatePEM(t, server.Certificate())
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(caData), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     ServerInfo
		wantErr bool
	}{
		{name: "CA data", cfg: ServerInfo{APIServer: server.URL, CACertData: caData}},
		{name: "CA file", cfg: ServerInfo{APIServer: server.URL, CAPath: caPath}},
		{name: "explicit insecure", cfg: ServerInfo{APIServer: server.URL, IgnoreTLS: true}},
		{name: "missing CA", cfg: ServerInfo{APIServer: server.URL}, wantErr: true},
		{name: "invalid CA", cfg: ServerInfo{APIServer: server.URL, CACertData: "not a certificate"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := RawRequest(context.Background(), test.cfg, defaultRawOptions("/ready"))
			if test.wantErr {
				if err == nil {
					t.Fatalf("body = %q, want error", body)
				}
				return
			}
			if err != nil || string(body) != "ok" {
				t.Fatalf("body = %q, err = %v", body, err)
			}
		})
	}

	otherCA, _, _, _ := makeMutualTLSCertificates(t)
	_, err := RawRequest(context.Background(), ServerInfo{
		APIServer:  server.URL,
		CACertData: otherCA,
	}, defaultRawOptions("/ready"))
	if err == nil {
		t.Fatal("request trusted an unrelated certificate authority")
	}
}

func TestRawRequestUsesInMemoryClientCertificate(t *testing.T) {
	caPEM, serverCertificate, clientCertificatePEM, clientKeyPEM := makeMutualTLSCertificates(t)
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("append client CA")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || request.TLS.PeerCertificates[0].Subject.CommonName != "peirates-client" {
			t.Error("request did not present the expected client certificate")
		}
		_, _ = writer.Write([]byte("authenticated"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	body, err := RawRequest(context.Background(), ServerInfo{
		APIServer:      server.URL,
		CACertData:     caPEM,
		ClientCertData: clientCertificatePEM,
		ClientKeyData:  clientKeyPEM,
	}, defaultRawOptions("/authenticated"))
	if err != nil || string(body) != "authenticated" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

func TestRawRequestRefusesRedirects(t *testing.T) {
	var redirected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Add(1)
			_, _ = writer.Write([]byte("must not be reached"))
			return
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	_, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL}, defaultRawOptions("/start"))
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusFound {
		t.Fatalf("error = %#v, want HTTP 302 status error", err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target requests = %d", redirected.Load())
	}
}

func TestRawRequestStatusClassificationAndBoundedDetail(t *testing.T) {
	const token = "sensitive-bearer"
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
				_, _ = writer.Write([]byte("denied\x00 " + token + "\n" + strings.Repeat("x", 100)))
			}))
			defer server.Close()
			options := defaultRawOptions("/resource")
			options.MaxErrorBodyBytes = 32
			_, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL, Token: token}, options)
			var statusError *HTTPStatusError
			if !errors.As(err, &statusError) {
				t.Fatalf("error = %#v, want HTTPStatusError", err)
			}
			if statusError.StatusCode != status || !statusError.DetailTruncated {
				t.Fatalf("status error = %#v", statusError)
			}
			if strings.Contains(statusError.Detail, token) || strings.ContainsRune(statusError.Detail, '\x00') || strings.Contains(statusError.Detail, "\n") {
				t.Fatalf("unsanitized detail = %q", statusError.Detail)
			}
			if len(statusError.Detail) > int(options.MaxErrorBodyBytes) {
				t.Fatalf("detail length = %d, limit = %d", len(statusError.Detail), options.MaxErrorBodyBytes)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked bearer token: %v", err)
			}
		})
	}
}

func TestRawRequestResponseBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/exact" {
			_, _ = writer.Write([]byte("1234"))
			return
		}
		_, _ = writer.Write([]byte("12345"))
	}))
	defer server.Close()
	options := defaultRawOptions("/exact")
	options.MaxResponseBytes = 4
	body, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL}, options)
	if err != nil || string(body) != "1234" {
		t.Fatalf("exact body = %q, err = %v", body, err)
	}
	options.APIPath = "/large"
	if _, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL}, options); !errors.Is(err, ErrRawResponseTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestRawRequestTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-time.After(250 * time.Millisecond):
			_, _ = writer.Write([]byte("late"))
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	options := defaultRawOptions("/slow")
	options.Timeout = 20 * time.Millisecond
	if _, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL}, options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	options.Timeout = time.Second
	if _, err := RawRequest(ctx, ServerInfo{APIServer: server.URL}, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestRawRequestRejectsPartialBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffered, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
		_ = buffered.Flush()
		_ = connection.Close()
	}))
	defer server.Close()

	body, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL}, defaultRawOptions("/partial"))
	if err == nil || body != nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

func TestRawRequestPreservesStatusWhenErrorBodyIsPartial(t *testing.T) {
	const token = "sensitive-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffered, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 403 " + token + "\r\nContent-Length: 20\r\n\r\ndenied")
		_ = buffered.Flush()
		_ = connection.Close()
	}))
	defer server.Close()

	_, err := RawRequest(context.Background(), ServerInfo{APIServer: server.URL, Token: token}, defaultRawOptions("/partial-error"))
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusForbidden {
		t.Fatalf("error = %#v, want HTTP 403 status error", err)
	}
	if statusError.Status != "403 Forbidden" || strings.Contains(err.Error(), token) {
		t.Fatalf("status error leaked or retained untrusted reason phrase: %#v", statusError)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want wrapped unexpected EOF", err)
	}
}

func TestAuthCanIResource(t *testing.T) {
	attributes := ResourceAttributes{
		Verb:        "get",
		Group:       "",
		Resource:    "nodes",
		Subresource: "proxy",
		Name:        "worker-a",
		Namespace:   "",
	}
	var calls int
	client := &Client{RawAPIRequest: func(ctx context.Context, cfg ServerInfo, options RawRequestOptions) ([]byte, error) {
		calls++
		if ctx == nil || cfg.Token != "token" {
			t.Fatalf("ctx = %v, cfg = %#v", ctx, cfg)
		}
		if options.Method != http.MethodPost || options.APIPath != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || options.ContentType != "application/json" {
			t.Fatalf("options = %#v", options)
		}
		var query struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Spec       struct {
				ResourceAttributes ResourceAttributes `json:"resourceAttributes"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(options.Body, &query); err != nil {
			t.Fatal(err)
		}
		if query.APIVersion != "authorization.k8s.io/v1" || query.Kind != "SelfSubjectAccessReview" || query.Spec.ResourceAttributes != attributes {
			t.Fatalf("query = %#v", query)
		}
		return []byte(`{"status":{"allowed":true}}`), nil
	}}
	allowed, err := client.AuthCanIResource(context.Background(), ServerInfo{UseAuthCanI: true, Token: "token"}, attributes)
	if err != nil || !allowed || calls != 1 {
		t.Fatalf("allowed = %v, calls = %d, err = %v", allowed, calls, err)
	}

	client.RawAPIRequest = func(context.Context, ServerInfo, RawRequestOptions) ([]byte, error) {
		calls++
		return nil, errors.New("must not be called")
	}
	allowed, err = client.AuthCanIResource(context.Background(), ServerInfo{UseAuthCanI: false}, attributes)
	if err != nil || !allowed || calls != 1 {
		t.Fatalf("disabled check: allowed = %v, calls = %d, err = %v", allowed, calls, err)
	}
}

func TestAuthCanIResourceDenialAndErrors(t *testing.T) {
	attributes := ResourceAttributes{Verb: "get", Resource: "nodes", Subresource: "proxy"}
	tests := []struct {
		name       string
		response   []byte
		requestErr error
		wantErr    bool
	}{
		{name: "denied", response: []byte(`{"status":{"allowed":false}}`)},
		{name: "malformed", response: []byte(`{`), wantErr: true},
		{name: "request failure", requestErr: errors.New("request failed"), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{RawAPIRequest: func(context.Context, ServerInfo, RawRequestOptions) ([]byte, error) {
				return test.response, test.requestErr
			}}
			allowed, err := client.AuthCanIResource(context.Background(), ServerInfo{UseAuthCanI: true}, attributes)
			if allowed || (err != nil) != test.wantErr {
				t.Fatalf("allowed = %v, err = %v", allowed, err)
			}
		})
	}
	if _, err := (&Client{}).AuthCanIResource(context.Background(), ServerInfo{UseAuthCanI: true}, ResourceAttributes{}); err == nil {
		t.Fatal("empty resource attributes unexpectedly succeeded")
	}
}

func makeMutualTLSCertificates(t *testing.T) (string, tls.Certificate, string, string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "peirates-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	issue := func(serial int64, commonName string, usages []x509.ExtKeyUsage, ipAddresses []net.IP) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  usages,
			IPAddresses:  ipAddresses,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	}
	serverCertPEM, serverKeyPEM := issue(2, "peirates-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	serverCertificate, err := tls.X509KeyPair([]byte(serverCertPEM), []byte(serverKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	clientCertPEM, clientKeyPEM := issue(3, "peirates-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	return string(caPEM), serverCertificate, clientCertPEM, clientKeyPEM
}

func TestRawRequestInputValidation(t *testing.T) {
	valid := defaultRawOptions("/path")
	tests := []struct {
		name    string
		ctx     context.Context
		options RawRequestOptions
	}{
		{name: "nil context", options: valid},
		{name: "missing method", ctx: context.Background(), options: RawRequestOptions{APIPath: "/path", Timeout: time.Second, MaxResponseBytes: 1, MaxErrorBodyBytes: 1}},
		{name: "missing path", ctx: context.Background(), options: RawRequestOptions{Method: http.MethodGet, Timeout: time.Second, MaxResponseBytes: 1, MaxErrorBodyBytes: 1}},
		{name: "zero timeout", ctx: context.Background(), options: RawRequestOptions{Method: http.MethodGet, APIPath: "/path", MaxResponseBytes: 1, MaxErrorBodyBytes: 1}},
		{name: "zero response limit", ctx: context.Background(), options: RawRequestOptions{Method: http.MethodGet, APIPath: "/path", Timeout: time.Second, MaxErrorBodyBytes: 1}},
		{name: "zero error limit", ctx: context.Background(), options: RawRequestOptions{Method: http.MethodGet, APIPath: "/path", Timeout: time.Second, MaxResponseBytes: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RawRequest(test.ctx, ServerInfo{APIServer: "http://127.0.0.1"}, test.options); err == nil {
				t.Fatal("request unexpectedly succeeded")
			}
		})
	}
}

func TestHTTPStatusErrorFormatting(t *testing.T) {
	errorValue := (&HTTPStatusError{StatusCode: 403, Status: "403 Forbidden", Detail: "denied", DetailTruncated: true}).Error()
	if errorValue != "kubernetes API returned 403 Forbidden: denied (detail truncated)" {
		t.Fatalf("error = %q", errorValue)
	}
	if fmt.Sprint(&HTTPStatusError{Status: "404 Not Found"}) != "kubernetes API returned 404 Not Found" {
		t.Fatal("status-only error formatting changed")
	}
}
