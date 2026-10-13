package app

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestKubectlCanICommandPreservesSession(t *testing.T) {
	original := launchKubectlCanI
	t.Cleanup(func() { launchKubectlCanI = original })
	session := NewSession(ServerInfo{Namespace: "current"})
	session.ServiceAccounts = []ServiceAccount{{}}
	session.ClientCertificates = []ClientCertificateKeyPair{{}}
	wantConnection := session.Connection
	wantAccounts := append([]ServiceAccount(nil), session.ServiceAccounts...)
	wantCertificates := append([]ClientCertificateKeyPair(nil), session.ClientCertificates...)
	called := false
	launchKubectlCanI = func(connection ServerInfo, accounts []ServiceAccount, certificates []ClientCertificateKeyPair, args []string, out io.Writer) error {
		called = true
		if !reflect.DeepEqual(connection, wantConnection) || !reflect.DeepEqual(accounts, wantAccounts) || !reflect.DeepEqual(certificates, wantCertificates) {
			t.Fatal("handler did not pass the current connection and stored identities")
		}
		if want := []string{"-n", "namespace", "create", "pods"}; !reflect.DeepEqual(args, want) {
			t.Fatalf("arguments = %q, want %q", args, want)
		}
		connection.Namespace = "changed"
		accounts[0] = ServiceAccount{Token: "changed"}
		certificates[0] = ClientCertificateKeyPair{Name: "changed"}
		_, _ = io.WriteString(out, "[+] Permitted: service account example\n")
		return errors.New("one identity could not be checked")
	}
	var output bytes.Buffer
	if !handleKubectlCanI("kubectl-can-i\t-n namespace create pods", session, &output) || !called {
		t.Fatal("authorization query was not handled")
	}
	if !reflect.DeepEqual(session.Connection, wantConnection) || !reflect.DeepEqual(session.ServiceAccounts, wantAccounts) || !reflect.DeepEqual(session.ClientCertificates, wantCertificates) {
		t.Fatal("authorization query changed the active session")
	}
	for _, want := range []string{"[+] Permitted:", "[kubectl-can-i] one identity could not be checked"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output %q does not contain %q", output.String(), want)
		}
	}
}

func TestKubectlCanIBareUsageAndCommandBoundary(t *testing.T) {
	original := launchKubectlCanI
	t.Cleanup(func() { launchKubectlCanI = original })
	calls := 0
	launchKubectlCanI = func(_ ServerInfo, _ []ServiceAccount, _ []ClientCertificateKeyPair, args []string, _ io.Writer) error {
		calls++
		if len(args) != 0 {
			t.Fatalf("bare command arguments = %q", args)
		}
		return errors.New("usage: kubectl-can-i [-n namespace | -A] [--subresource name] VERB RESOURCE[/NAME]")
	}
	var output bytes.Buffer
	session := NewSession(ServerInfo{})
	if !handleKubectlCanI("kubectl-can-i", session, &output) || !strings.Contains(output.String(), "usage: kubectl-can-i") {
		t.Fatalf("bare command did not print usage: %s", output.String())
	}
	for _, input := range []string{"", "kubectl get pods", "kubectl-can-i-extra create pods", "kubectl-try-all create pods"} {
		if handleKubectlCanI(input, session, &output) {
			t.Errorf("unrelated command %q was intercepted", input)
		}
	}
	if calls != 1 {
		t.Fatalf("launcher calls = %d, want 1", calls)
	}
}
