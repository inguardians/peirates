package kubectlcani

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/model"
	"k8s.io/client-go/tools/clientcmd"
)

type exitStatus int

func (e exitStatus) Error() string { return "secret-bearing error" }
func (e exitStatus) ExitCode() int { return int(e) }

func TestParseArgs(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want []string
	}{
		{"namespace before action", []string{"-n", "team", "create", "pods"}, []string{"auth", "can-i", "create", "pods", "--namespace=team"}},
		{"namespace equals after action", []string{"get", "pods/example", "--namespace=team"}, []string{"auth", "can-i", "get", "pods/example", "--namespace=team"}},
		{"short namespace equals", []string{"get", "pods", "-n=team"}, []string{"auth", "can-i", "get", "pods", "--namespace=team"}},
		{"short namespace attached", []string{"get", "pods", "-nteam"}, []string{"auth", "can-i", "get", "pods", "--namespace=team"}},
		{"all namespaces", []string{"-A", "list", "pods"}, []string{"auth", "can-i", "list", "pods", "--all-namespaces"}},
		{"all namespaces equals", []string{"--all-namespaces=true", "list", "pods"}, []string{"auth", "can-i", "list", "pods", "--all-namespaces"}},
		{"subresource", []string{"get", "nodes", "--subresource", "proxy"}, []string{"auth", "can-i", "get", "nodes", "--subresource=proxy"}},
		{"nonresource", []string{"get", "/healthz"}, []string{"auth", "can-i", "get", "/healthz"}},
		{"wildcards and api group", []string{"*", "deployments.apps"}, []string{"auth", "can-i", "*", "deployments.apps"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseArgs = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	for _, args := range [][]string{
		nil, {"create"}, {"create", "pods", "extra"}, {"-n", "", "create", "pods"},
		{"-n", "team", "-A", "get", "pods"}, {"--subresource=", "get", "pods"},
		{"--subresource=proxy", "get", "/healthz"}, {"--token=secret", "get", "pods"},
		{"--server=https://other", "get", "pods"}, {"--kubeconfig=/other", "get", "pods"},
		{"--as=admin", "get", "pods"}, {"--list"}, {"--quiet", "get", "pods"},
		{"--help"}, {"--", "--token=secret", "pods"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("accepted invalid arguments %q", args)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("leaked argument in error: %v", err)
		}
	}
}

func TestRunIsolatesCredentialsAndCleansUp(t *testing.T) {
	t.Setenv("KUBECONFIG", "/ambient/must-not-be-used")
	base := model.ServerInfo{APIServer: "https://base", Token: "active-token", TokenName: "active-token-name", ClientCertData: "active-cert", ClientKeyData: "active-key", ClientCertName: "active-cert-name", CACertData: "base-ca", Namespace: "current", UseAuthCanI: false}
	original := base
	accounts := []model.ServiceAccount{{Name: "stored", Token: "stored-token"}, {Name: "alias", Token: "stored-token"}, {Name: "active-stored", Token: "active-token"}}
	certs := []model.ClientCertificateKeyPair{{Name: "cert", ClientCertificateData: "stored-cert", ClientKeyData: "stored-key", APIServer: "https://cert-server", CACert: "cert-ca"}}
	var paths []string
	var credentials []string
	var out bytes.Buffer
	err := run(base, accounts, certs, []string{"-n", "requested", "create", "pods"}, &out, func(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
		configPath := strings.TrimPrefix(args[0], "--kubeconfig=")
		paths = append(paths, configPath)
		info, err := os.Stat(configPath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("kubeconfig permissions: %v, %v", info, err)
		}
		dirInfo, err := os.Stat(filepath.Dir(configPath))
		if err != nil || dirInfo.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions: %v, %v", dirInfo, err)
		}
		config, err := clientcmd.LoadFromFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(config.AuthInfos) != 1 || len(config.Clusters) != 1 || len(config.Contexts) != 1 || config.CurrentContext != "check" {
			t.Fatalf("unexpected kubeconfig contents: %v", config)
		}
		auth := config.AuthInfos["identity"]
		cluster := config.Clusters["target"]
		if auth.Token != "" {
			credentials = append(credentials, auth.Token)
			if len(auth.ClientCertificateData) != 0 || len(auth.ClientKeyData) != 0 || cluster.Server != "https://base" || string(cluster.CertificateAuthorityData) != "base-ca" {
				t.Fatal("service account inherited certificate connection")
			}
		} else {
			credentials = append(credentials, string(auth.ClientCertificateData))
			if string(auth.ClientCertificateData) == "stored-cert" && (cluster.Server != "https://cert-server" || string(cluster.CertificateAuthorityData) != "cert-ca") {
				t.Fatal("stored certificate lost its server or CA")
			}
		}
		if config.Contexts["check"].Namespace != "current" || !reflect.DeepEqual(args[2:], []string{"--request-timeout=10s", "auth", "can-i", "create", "pods", "--namespace=requested"}) {
			t.Fatalf("namespace/action propagation: %v", args)
		}
		if auth.Exec != nil || auth.AuthProvider != nil || auth.Impersonate != "" || auth.TokenFile != "" {
			t.Fatal("unexpected alternate authentication")
		}
		fmt.Fprintln(stdout, "Warning: discovery warning\nyes")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(credentials, []string{"stored-token", "active-token", "stored-cert", "active-cert"}) {
		t.Fatalf("checked credentials = %v", credentials)
	}
	if base != original {
		t.Fatal("active session changed")
	}
	for _, path := range paths {
		if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Errorf("temporary credentials remain: %v", err)
		}
	}
	for _, want := range []string{`Permitted: service account "stored"`, `Permitted: service account "alias"`, `Permitted: certificate "cert"`, `Permitted: certificate "active-cert-name"`, "5 permitted, 0 denied, 0 failed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestRunDenialFailureAndRedaction(t *testing.T) {
	for _, tt := range []struct {
		name, response string
		runnerErr      error
		want           string
		failed         bool
	}{
		{"allowed", "yes\n", nil, "1 permitted, 0 denied, 0 failed", false},
		{"denied", "no\n", exitStatus(1), "0 permitted, 1 denied, 0 failed", false},
		{"denied with reason", "Warning: text\nno - confidential-reason\n", exitStatus(1), "0 permitted, 1 denied, 0 failed", false},
		{"unauthorized", "error: secret-token\n", exitStatus(1), "0 permitted, 0 denied, 1 failed", true},
		{"unexpected success", "secret-token\n", nil, "0 permitted, 0 denied, 1 failed", true},
		{"yes with failed process", "yes\n", exitStatus(1), "0 permitted, 0 denied, 1 failed", true},
		{"no with killed process", "no\n", exitStatus(-1), "0 permitted, 0 denied, 1 failed", true},
		{"transport failure", "", errors.New("secret-token"), "0 permitted, 0 denied, 1 failed", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			var tempPath string
			err := run(model.ServerInfo{APIServer: "https://server", Token: "secret-token", IgnoreTLS: true}, nil, nil, []string{"get", "pods"}, &out, func(_ io.Reader, stdout, stderr io.Writer, args ...string) error {
				tempPath = strings.TrimPrefix(args[0], "--kubeconfig=")
				fmt.Fprint(stdout, tt.response)
				fmt.Fprintln(stderr, "secret-token")
				return tt.runnerErr
			})
			if (err != nil) != tt.failed || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("result %v, output %s", err, out.String())
			}
			if strings.Contains(out.String(), "secret-token") || strings.Contains(out.String(), "confidential-reason") {
				t.Fatal("credential or raw diagnostic leaked")
			}
			if _, err := os.Stat(filepath.Dir(tempPath)); !os.IsNotExist(err) {
				t.Fatal("temporary directory remains")
			}
		})
	}
}

func TestRunContinuesAfterIncompleteCredential(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	err := run(model.ServerInfo{APIServer: "https://server", IgnoreTLS: true}, []model.ServiceAccount{{Name: "missing"}, {Name: "works", Token: "token"}}, []model.ClientCertificateKeyPair{{Name: "partial", ClientCertificateData: "cert"}}, []string{"get", "pods"}, &out, func(_ io.Reader, stdout, _ io.Writer, _ ...string) error {
		calls++
		fmt.Fprintln(stdout, "yes")
		return nil
	})
	if err == nil || calls != 1 || !strings.Contains(out.String(), "1 permitted, 0 denied, 2 failed") {
		t.Fatalf("calls=%d err=%v output=%s", calls, err, out.String())
	}
}

func TestRunRejectsInvalidArgumentsBeforeExecution(t *testing.T) {
	err := run(model.ServerInfo{Token: "token"}, nil, nil, []string{"--as=admin", "get", "pods"}, io.Discard, func(_ io.Reader, _, _ io.Writer, _ ...string) error {
		t.Fatal("executed invalid request")
		return nil
	})
	if err == nil {
		t.Fatal("expected invalid argument error")
	}
}

func TestCheckReadsCAPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte("ca-from-file"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := check(model.ServerInfo{APIServer: "https://server", Token: "token", CAPath: path}, []string{"auth", "can-i", "get", "pods"}, func(_ io.Reader, stdout, _ io.Writer, args ...string) error {
		config, err := clientcmd.LoadFromFile(strings.TrimPrefix(args[0], "--kubeconfig="))
		if err != nil {
			t.Fatal(err)
		}
		if string(config.Clusters["target"].CertificateAuthorityData) != "ca-from-file" {
			t.Fatal("CA file was not embedded")
		}
		fmt.Fprintln(stdout, "yes")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
