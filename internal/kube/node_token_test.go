package kube

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

func TestResolveNodeTokenTarget(t *testing.T) {
	ca, _, _, _ := makeMutualTLSCertificates(t)
	otherCA, _, _, _ := makeMutualTLSCertificates(t)
	for _, test := range []struct {
		name       string
		cfg        ServerInfo
		podCA      string
		host       string
		wantErr    error
		wantServer string
	}{
		{name: "in cluster", host: "10.0.0.1", podCA: ca, wantServer: "https://10.0.0.1:443"},
		{name: "IPv6", host: "fd00::1", podCA: ca, wantServer: "https://[fd00::1]:443"},
		{name: "explicit same trust", cfg: ServerInfo{APIServer: "https://eks.example", CACertData: ca}, host: "10.0.0.1", podCA: ca, wantServer: "https://eks.example"},
		{name: "different trust", cfg: ServerInfo{APIServer: "https://eks.example", CACertData: otherCA}, host: "10.0.0.1", podCA: ca, wantErr: ErrNodeTokenTargetMismatch},
		{name: "untrusted explicit target", cfg: ServerInfo{APIServer: "https://other.example"}, host: "10.0.0.1", podCA: ca, wantErr: ErrNodeTokenTargetMismatch},
		{name: "no target", wantErr: ErrNodeTokenTargetUnavailable},
		{name: "missing trust", cfg: ServerInfo{APIServer: "https://eks.example"}, wantErr: ErrNodeTokenTargetUnavailable},
		{name: "explicit insecure", cfg: ServerInfo{APIServer: "https://eks.example", IgnoreTLS: true}, wantServer: "https://eks.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := test.cfg
			getenv := func(key string) string {
				if key == "KUBERNETES_SERVICE_HOST" {
					return test.host
				}
				return ""
			}
			read := func(path string) ([]byte, error) {
				switch path {
				case "/pod/ca.crt":
					if test.podCA != "" {
						return []byte(test.podCA), nil
					}
				case "/pod/namespace":
					return []byte("work\n"), nil
				case "/pod/token":
					t.Fatal("must not read ambient token")
				}
				return nil, os.ErrNotExist
			}
			got, err := resolveNodeTokenTarget(test.cfg, getenv, read, "/pod/")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error %v, want %v", err, test.wantErr)
			}
			if err == nil && (got.APIServer != test.wantServer || got.Namespace != "work") {
				t.Fatalf("unexpected target: %s ns=%s", got.APIServer, got.Namespace)
			}
			if test.cfg != before {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestVerifyNodeTokenIsolatedIdentity(t *testing.T) {
	ca, cert, _, _ := makeMutualTLSCertificates(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" || r.Header.Get("Authorization") != "Bearer k8s-aws-v1.test" {
			t.Error("wrong request")
		}
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("ambient certificate used")
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["kind"] != "SelfSubjectReview" {
			t.Error("bad review body")
		}
		_, _ = io.WriteString(w, `{"status":{"userInfo":{"username":"system:node:i-1234","groups":["system:nodes","system:authenticated"]}}}`)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	cfg := ServerInfo{APIServer: server.URL, CACertData: ca, Token: "old", ClientCertData: "invalid ambient cert", ClientKeyData: "invalid ambient key", ActiveTokenKind: "eks-node", ActiveTokenExpiresAt: time.Now().Add(-time.Hour)}
	before := cfg
	got, err := VerifyNodeToken(context.Background(), cfg, "k8s-aws-v1.test")
	if err != nil || got.Username != "system:node:i-1234" || len(got.Groups) != 2 {
		t.Fatalf("identity=%v err=%v", got, err)
	}
	if cfg != before {
		t.Fatal("connection mutated")
	}
}

func TestVerifyNodeTokenFailureOutcomes(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body, want string
	}{
		{"unauthorized", 401, "k8s-aws-v1.secret", "authentication rejected"},
		{"forbidden", 403, "sensitive body", "inspection denied"},
		{"unsupported", 404, "sensitive body", "unavailable"},
		{"redirect", 302, "sensitive body", "HTTP 302"},
		{"invalid", 200, "{", "invalid SelfSubjectReview"},
		{"non node", 200, `{"status":{"userInfo":{"username":"admin","groups":["system:nodes"]}}}`, "not a Kubernetes node"},
		{"missing group", 200, `{"status":{"userInfo":{"username":"system:node:worker","groups":["system:authenticated"]}}}`, "lacks system:nodes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://should-not-follow.invalid")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			_, err := VerifyNodeToken(context.Background(), ServerInfo{APIServer: server.URL, CACertData: certificatePEM(t, server.Certificate())}, "k8s-aws-v1.secret")
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "sensitive body") || strings.Contains(err.Error(), "k8s-aws-v1.secret") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestActiveNodeTokenKubectlIsolationAndCleanup(t *testing.T) {
	t.Setenv("KUBECONFIG", "/must-not-load")
	var configPath string
	client := &Client{RunCommand: func(_ io.Reader, _, _ io.Writer, args ...string) error {
		for _, arg := range args {
			if strings.Contains(arg, "k8s-aws-v1.secret") {
				t.Fatal("token leaked to argv")
			}
		}
		configPath = strings.TrimPrefix(args[0], "--kubeconfig=")
		info, err := os.Stat(configPath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("config mode: %v %v", info, err)
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		config, err := clientcmd.Load(data)
		if err != nil {
			t.Fatal(err)
		}
		auth := config.AuthInfos["node"]
		if auth == nil || auth.Token != "k8s-aws-v1.secret" || auth.Exec != nil || auth.ClientCertificate != "" || len(auth.ClientCertificateData) != 0 {
			t.Fatal("credential isolation failed")
		}
		if config.Clusters["target"].Server != "https://target" {
			t.Fatal("wrong target")
		}
		return errors.New("runner failed")
	}}
	cfg := ServerInfo{APIServer: "https://target", Token: "k8s-aws-v1.secret", ClientCertData: "ambient", ClientKeyData: "ambient", IgnoreTLS: true, ActiveTokenKind: "eks-node", ActiveTokenExpiresAt: time.Now().Add(time.Minute)}
	if err := client.RunWithConfig(cfg, nil, io.Discard, io.Discard, "get", "pods"); err == nil || err.Error() != "runner failed" {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(filepath.Dir(configPath)); !os.IsNotExist(err) {
		t.Fatal("temporary credentials not cleaned")
	}
	for _, args := range [][]string{{"--token=override"}, {"-shttps://other"}, {"--context", "ambient"}, {"--as", "admin"}} {
		if err := client.RunWithConfig(cfg, nil, io.Discard, io.Discard, args...); err == nil || !strings.Contains(err.Error(), "override") {
			t.Fatalf("override accepted: %v %v", args, err)
		}
	}
}

func TestActiveNodeTokenExpiryAndSwitch(t *testing.T) {
	cfg := ServerInfo{APIServer: "https://unused", Token: "expired", ActiveTokenKind: "eks-node", ActiveTokenExpiresAt: time.Now().Add(-time.Minute)}
	client := &Client{RunCommand: func(io.Reader, io.Writer, io.Writer, ...string) error {
		t.Fatal("expired token reached runner")
		return nil
	}}
	if _, _, err := client.Run(cfg, "get", "pods"); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := RawRequest(context.Background(), cfg, defaultRawOptions("/api")); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("raw expiry: %v", err)
	}
	if err := DoAPIRequest(cfg, "GET", "api", nil, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("API expiry: %v", err)
	}
	if client.AuthCanI(cfg, "get", "pods") {
		t.Fatal("disabled precheck bypassed expiry")
	}
	AssignServiceAccount(ServiceAccount{Name: "new", Token: "new"}, &cfg)
	if err := CheckActiveToken(cfg); err != nil || cfg.ActiveTokenKind != "" || !reflect.DeepEqual(cfg.ActiveTokenExpiresAt, time.Time{}) {
		t.Fatal("service account inherited node expiry")
	}
}
