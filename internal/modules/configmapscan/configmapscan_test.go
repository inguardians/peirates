package configmapscan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/inguardians/peirates/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testJWT() string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`)) + ".c2ln"
}

func TestStoredIdentitiesDoNotInheritNodeExpiry(t *testing.T) {
	base := model.ServerInfo{APIServer: "https://api", Token: "node-token", ActiveTokenKind: "eks-node", ActiveTokenExpiresAt: time.Now().Add(-time.Minute)}
	ids := identities(base, []model.ServiceAccount{{Name: "stored", Token: "stored-token"}}, nil)
	if len(ids) != 2 || ids[0].cfg.ActiveTokenKind != "eks-node" || ids[1].cfg.ActiveTokenKind != "" || !ids[1].cfg.ActiveTokenExpiresAt.IsZero() {
		t.Fatal("stored service account inherited active node token metadata")
	}
	if _, err := listPage(context.Background(), base, "", ""); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry check = %v", err)
	}
}

func TestDetectCredentialFormats(t *testing.T) {
	cases := []struct{ name, value, want string }{
		{"embedded JWT", "prefix=" + testJWT() + ";tail", "JWT-shaped token"},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----", "private key block"},
		{"RSA key", "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----", "private key block"},
		{"PKCS8 key", "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----", "private key block"},
		{"AWS temporary", "key=ASIAABCDEFGHIJKLMNOP", "AWS access key ID"},
		{"AWS long lived", "key=AKIAABCDEFGHIJKLMNOP", "AWS access key ID"},
		{"Google access token", "token=ya29.abcdefghijklmnop", "Google OAuth access token candidate"},
		{"Google service account key", `{"type":"service_account","client_email":"a@b","private_key":"key"}`, "Google service account key"},
		{"Azure SAS", "https://example.invalid/blob?sv=2025-01-01&sp=r&sig=abcdef", "Azure Storage credential candidate"},
		{"Azure connection string", "DefaultEndpointsProtocol=https;AccountName=example;AccountKey=abcdef;EndpointSuffix=core.windows.net", "Azure Storage credential candidate"},
		{"Azure client secret", `{"tenantId":"t","clientId":"c","clientSecret":"s"}`, "Azure client secret settings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detect([]byte(tc.value))
			for _, match := range got {
				if match.kind == tc.want {
					return
				}
			}
			t.Fatalf("%s detector missing: %#v", tc.want, got)
		})
	}
}

func TestDetectRejectsLookalikes(t *testing.T) {
	for _, value := range []string{
		"eyJbad.payload.signature", "a" + testJWT(), testJWT() + "a", "AKIASHORT", "ya29.short", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----", `{"type":"service_account","client_email":"a@b"}`, `{"tenantId":"t","clientId":"c"}`, "https://example.invalid/?sv=1",
	} {
		if got := detect([]byte(value)); len(got) != 0 {
			t.Errorf("unexpected match for %q: %#v", value, got)
		}
	}
}

func TestRunFallsBackPaginatesAndRedacts(t *testing.T) {
	secret := testJWT()
	var calls []string
	request := func(_ context.Context, cfg model.ServerInfo, namespace, cursor string) (corev1.ConfigMapList, error) {
		calls = append(calls, cfg.Token+":"+namespace+":"+cursor)
		if namespace == "" {
			return corev1.ConfigMapList{}, &statusError{code: http.StatusForbidden}
		}
		if cursor == "" {
			return corev1.ConfigMapList{ListMeta: metav1.ListMeta{Continue: "next"}, Items: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "app"}, Data: map[string]string{"creds": "inline " + secret}}}}, nil
		}
		return corev1.ConfigMapList{Items: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "app"}, BinaryData: map[string][]byte{"key": []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----")}}}}, nil
	}
	var out bytes.Buffer
	base := model.ServerInfo{APIServer: "https://api", Namespace: "app", Token: "active-secret"}
	accounts := []model.ServiceAccount{{Name: "duplicate", Token: "active-secret"}}
	if err := run(context.Background(), base, accounts, nil, &out, request); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"cluster list forbidden", "namespace \"app\" complete (2 ConfigMaps)", "JWT-shaped token", "private key block", "active service account, service account #1 \"duplicate\""} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q: %s", want, got)
		}
	}
	for _, leak := range []string{secret, "active-secret", "YWJj"} {
		if strings.Contains(got, leak) {
			t.Errorf("output leaked credential %q", leak)
		}
	}
	if len(calls) != 3 || calls[0] != "active-secret::" || calls[1] != "active-secret:app:" || calls[2] != "active-secret:app:next" {
		t.Fatalf("unexpected calls: %#v", calls)
	}
}

func TestRunIncompleteDoesNotExposeErrors(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), model.ServerInfo{Token: "sensitive", APIServer: "https://api"}, nil, nil, &out, func(context.Context, model.ServerInfo, string, string) (corev1.ConfigMapList, error) {
		return corev1.ConfigMapList{}, errors.New("sensitive: server failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "incomplete: transport failure") || strings.Contains(got, "sensitive") {
		t.Fatalf("unexpected output: %s", got)
	}
}

func TestIdentitiesPreserveConnectionSettings(t *testing.T) {
	base := model.ServerInfo{APIServer: "https://base", Token: "active-token", Namespace: "app", CACertData: "base-ca", IgnoreTLS: true, UseAuthCanI: true}
	ids := identities(base,
		[]model.ServiceAccount{{Name: "app/reader", Token: "reader-token"}},
		[]model.ClientCertificateKeyPair{{Name: "cert-reader", ClientCertificateData: "cert", ClientKeyData: "key", APIServer: "https://cert-api", CACert: "cert-ca"}},
	)
	if len(ids) != 3 {
		t.Fatalf("identities=%d", len(ids))
	}
	if ids[1].cfg.Token != "reader-token" || ids[1].cfg.Namespace != "app" || ids[1].cfg.CACertData != "base-ca" || !ids[1].cfg.IgnoreTLS || !ids[1].cfg.UseAuthCanI {
		t.Fatalf("service account config not preserved: %#v", ids[1].cfg)
	}
	if ids[2].cfg.Token != "" || ids[2].cfg.ClientCertData != "cert" || ids[2].cfg.ClientKeyData != "key" || ids[2].cfg.APIServer != "https://cert-api" || ids[2].cfg.CACertData != "cert-ca" || ids[2].cfg.Namespace != "app" {
		t.Fatalf("certificate config incorrect: %#v", ids[2].cfg)
	}
	if base.Token != "active-token" || base.APIServer != "https://base" {
		t.Fatal("base config mutated")
	}
}

func TestRunMarksRepeatedCursorIncomplete(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), model.ServerInfo{Token: "token", APIServer: "https://api"}, nil, nil, &out, func(context.Context, model.ServerInfo, string, string) (corev1.ConfigMapList, error) {
		return corev1.ConfigMapList{ListMeta: metav1.ListMeta{Continue: "repeat"}}, nil
	})
	if err != nil || !strings.Contains(out.String(), "incomplete: repeated page cursor") {
		t.Fatalf("err=%v output=%q", err, out.String())
	}
}

func TestRunKeepsFindingsSeparateAcrossAPIServers(t *testing.T) {
	var out bytes.Buffer
	base := model.ServerInfo{APIServer: "https://first.example", Token: "token", Namespace: "app"}
	certs := []model.ClientCertificateKeyPair{{Name: "reader", ClientCertificateData: "cert", ClientKeyData: "key", APIServer: "https://second.example"}}
	err := run(context.Background(), base, nil, certs, &out, func(_ context.Context, _ model.ServerInfo, _, _ string) (corev1.ConfigMapList, error) {
		return corev1.ConfigMapList{Items: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "app"}, Data: map[string]string{"credential": testJWT()}}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Count(got, "Finding: ") != 2 || !strings.Contains(got, "API server \"https://first.example\"") || !strings.Contains(got, "API server \"https://second.example\"") || !strings.Contains(got, "Findings: 2") {
		t.Fatalf("different API servers were merged: %s", got)
	}
}

func TestListPageBearerAndPagination(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer token-value" || r.URL.Path != "/api/v1/configmaps" || r.URL.Query().Get("limit") != "10" || r.URL.Query().Get("continue") != "next/cursor" {
			t.Errorf("unexpected request: authorization=%q path=%q query=%q", r.Header.Get("Authorization"), r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"kind":"ConfigMapList","metadata":{},"items":[]}`))
	}))
	defer server.Close()
	_, err := listPage(context.Background(), model.ServerInfo{APIServer: server.URL, Token: "token-value"}, "", "next/cursor")
	if err != nil || requests != 1 {
		t.Fatalf("listPage: requests=%d err=%v", requests, err)
	}
}

func TestListPageClientCertificate(t *testing.T) {
	certPEM, keyPEM := testClientCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.Header.Get("Authorization") != "" {
			t.Error("client certificate not sent or unexpected bearer token")
		}
		_, _ = w.Write([]byte(`{"kind":"ConfigMapList","metadata":{},"items":[]}`))
	}))
	server.TLS = server.Config.TLSConfig
	if server.TLS == nil {
		server.TLS = &tls.Config{}
	}
	server.TLS.ClientAuth = tls.RequestClientCert
	server.StartTLS()
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	_, err := listPage(context.Background(), model.ServerInfo{APIServer: server.URL, CACertData: string(ca), ClientCertData: string(certPEM), ClientKeyData: string(keyPEM)}, "", "")
	if err != nil {
		t.Fatal(err)
	}
}

func testClientCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKey})
}
