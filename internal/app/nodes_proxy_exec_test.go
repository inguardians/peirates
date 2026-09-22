package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
	"github.com/inguardians/peirates/internal/modules/nodesproxyexec"
)

type fakeNodesProxyReviewer struct {
	mu    sync.Mutex
	calls map[string]int
}

func (reviewer *fakeNodesProxyReviewer) ReviewAccess(_ context.Context, connection model.ServerInfo, request nodesproxyexec.AccessRequest) (bool, error) {
	reviewer.mu.Lock()
	reviewer.calls[connection.Token+"/"+request.Verb]++
	reviewer.mu.Unlock()
	if request.NodeName != "worker-1" {
		return false, fmt.Errorf("unexpected node %q", request.NodeName)
	}
	if connection.ClientCertData != "" || connection.ClientKeyData != "" || connection.ClientCertName != "" {
		return false, fmt.Errorf("client certificate identity was not cleared")
	}
	switch connection.Token {
	case "token-allowed", "token-allowed-two":
		return request.Verb == "get", nil
	case "token-error":
		return false, fmt.Errorf("review failed for token-error")
	default:
		return false, nil
	}
}

type fakeNodesProxyFactory struct {
	client     *fakeNodesProxyKubelet
	connection model.ServerInfo
}

func (factory *fakeNodesProxyFactory) NewKubelet(_ context.Context, connection model.ServerInfo) (nodesproxyexec.Kubelet, error) {
	factory.connection = connection
	return factory.client, nil
}

type fakeNodesProxyKubelet struct {
	targets   []nodesproxyexec.Target
	probe     int
	lists     int
	execs     int
	execArgv  []string
	execToken string
}

func (client *fakeNodesProxyKubelet) Probe(context.Context) error {
	client.probe++
	return nil
}

func (client *fakeNodesProxyKubelet) ListRunningContainers(context.Context) ([]nodesproxyexec.Target, error) {
	client.lists++
	return append([]nodesproxyexec.Target(nil), client.targets...), nil
}

func (client *fakeNodesProxyKubelet) Exec(_ context.Context, _ nodesproxyexec.Target, argv []string, stdout, stderr io.Writer) (nodesproxyexec.ExecStatus, error) {
	client.execs++
	client.execArgv = append([]string(nil), argv...)
	_, _ = io.WriteString(stdout, "uid=1000(test)\n")
	_, _ = io.WriteString(stderr, "bounded warning\n")
	return nodesproxyexec.ExecStatus{ExitCode: 0, Protocol: "v5.channel.k8s.io", Complete: true}, nil
}

func installNodesProxyFakes(t *testing.T, reviewer nodesproxyexec.AccessReviewer, factory nodesproxyexec.KubeletFactory) {
	t.Helper()
	originalReviewer := newNodesProxyAccessReviewer
	originalFactory := newNodesProxyKubeletFactory
	t.Cleanup(func() {
		newNodesProxyAccessReviewer = originalReviewer
		newNodesProxyKubeletFactory = originalFactory
	})
	newNodesProxyAccessReviewer = func() nodesproxyexec.AccessReviewer { return reviewer }
	newNodesProxyKubeletFactory = func(string, kube.KubeletTLSOptions) nodesproxyexec.KubeletFactory { return factory }
}

func TestLaunchNodesProxyExecReviewsAllTokensAndExecutesExplicitSelection(t *testing.T) {
	reviewer := &fakeNodesProxyReviewer{calls: make(map[string]int)}
	client := &fakeNodesProxyKubelet{targets: []nodesproxyexec.Target{{
		NodeName: "worker-1", Namespace: "target-ns", PodName: "target-pod", ContainerName: "target-container", ContainerKind: nodesproxyexec.ContainerRegular,
	}}}
	factory := &fakeNodesProxyFactory{client: client}
	installNodesProxyFakes(t, reviewer, factory)

	connection := ServerInfo{
		APIServer: "https://api.example", Token: "active-token", TokenName: "active",
		ClientCertData: "certificate", ClientKeyData: "key", ClientCertName: "certificate-name", UseAuthCanI: true,
	}
	accounts := []ServiceAccount{
		{Name: "active", Token: "token-denied", DiscoveryMethod: "startup"},
		{Name: "allowed\x1b", Token: "token-allowed", DiscoveryMethod: "secret\nread"},
		{Name: "later", Token: "token-error", DiscoveryMethod: "node filesystem"},
	}
	input := strings.Join([]string{
		"", // accept NODE_NAME
		"1",
		"https://10.0.0.2:10250",
		"", // accept insecure TLS mode
		"0",
		"", // default id
		"",
	}, "\n")
	var stdout, stderr strings.Builder
	err := launchNodesProxyExecWithStreams(context.Background(), connection, accounts, strings.NewReader(input), &stdout, &stderr, func(name string) string {
		if name == "NODE_NAME" {
			return " worker-1 "
		}
		return ""
	})
	if err != nil {
		t.Fatalf("launchNodesProxyExecWithStreams: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	for _, token := range []string{"token-denied", "token-allowed", "token-error"} {
		if reviewer.calls[token+"/get"] != 1 {
			t.Errorf("get reviews for %s = %d, want 1", token, reviewer.calls[token+"/get"])
		}
	}
	if reviewer.calls["token-allowed/create"] != 1 {
		t.Errorf("create negative-control reviews = %d, want 1", reviewer.calls["token-allowed/create"])
	}
	if factory.connection.Token != "token-allowed" || factory.connection.TokenName != "allowed\x1b" {
		t.Fatalf("factory selected connection = %#v", factory.connection)
	}
	if client.probe != 1 || client.lists != 2 || client.execs != 1 {
		t.Fatalf("kubelet calls probe/list/exec = %d/%d/%d, want 1/2/1", client.probe, client.lists, client.execs)
	}
	if fmt.Sprint(client.execArgv) != "[id]" {
		t.Fatalf("exec argv = %#v, want [id]", client.execArgv)
	}

	output := stdout.String() + stderr.String()
	for _, secret := range []string{"token-denied", "token-allowed", "token-error", "active-token"} {
		if strings.Contains(output, secret) {
			t.Errorf("output leaked credential %q:\n%s", secret, output)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(secret)))
		if strings.Contains(output, digest) {
			t.Errorf("output leaked digest for %q", secret)
		}
	}
	if strings.Contains(output, "\x1b") || strings.Contains(output, "\nread") {
		t.Fatalf("output retained terminal control characters: %q", output)
	}
	for _, want := range []string{
		"Stored token RBAC results for node worker-1:",
		`[0] name="active" method="startup" get nodes/proxy=denied`,
		`[1] name="allowed" method="secretread" get nodes/proxy=allowed create nodes/proxy=denied`,
		`[2] name="later" method="node filesystem" get nodes/proxy=error`,
		"[0] target-ns/target-pod/target-container kind=regular node=worker-1",
		"Argv: [\"id\"]",
		"uid=1000(test)",
		"bounded warning",
		"Result classification: confirmed-get-only-exec",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q:\n%s", want, output)
		}
	}
	if connection.Token != "active-token" || accounts[1].Token != "token-allowed" {
		t.Fatalf("caller state mutated: connection=%#v accounts=%#v", connection, accounts)
	}
}

func TestLaunchNodesProxyExecExecutesWithoutFinalConfirmation(t *testing.T) {
	reviewer := &fakeNodesProxyReviewer{calls: make(map[string]int)}
	client := &fakeNodesProxyKubelet{targets: []nodesproxyexec.Target{{
		NodeName: "worker-1", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: nodesproxyexec.ContainerRegular,
	}}}
	factory := &fakeNodesProxyFactory{client: client}
	installNodesProxyFakes(t, reviewer, factory)
	lines := []string{"worker-1", "0", "https://node.example:10250", "insecure", "0", "id", ""}
	var stdout, stderr strings.Builder
	err := launchNodesProxyExecWithStreams(context.Background(), ServerInfo{UseAuthCanI: true}, []ServiceAccount{{Name: "allowed", Token: "token-allowed"}}, strings.NewReader(strings.Join(lines, "\n")), &stdout, &stderr, func(string) string { return "" })
	if err != nil {
		t.Fatalf("launchNodesProxyExecWithStreams: %v", err)
	}
	if client.execs != 1 {
		t.Fatalf("Exec calls = %d, want 1", client.execs)
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, "EXEC-VIA-NODES-PROXY") || strings.Contains(output, "bypasses API-server admission") {
		t.Fatalf("output contains removed warning or confirmation: %q", output)
	}
}

func TestLaunchNodesProxyExecSelectsAmongMultipleQualifyingTokens(t *testing.T) {
	reviewer := &fakeNodesProxyReviewer{calls: make(map[string]int)}
	client := &fakeNodesProxyKubelet{targets: []nodesproxyexec.Target{{
		NodeName: "worker-1", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: nodesproxyexec.ContainerRegular,
	}}}
	factory := &fakeNodesProxyFactory{client: client}
	installNodesProxyFakes(t, reviewer, factory)
	accounts := []ServiceAccount{
		{Name: "first allowed", Token: "token-allowed"},
		{Name: "second allowed", Token: "token-allowed-two"},
	}
	input := strings.Join([]string{
		"worker-1", "1", "https://node.example:10250", "insecure",
		"0", "cat /etc/shadow", "",
	}, "\n")
	var stdout, stderr strings.Builder
	err := launchNodesProxyExecWithStreams(context.Background(), ServerInfo{UseAuthCanI: true}, accounts, strings.NewReader(input), &stdout, &stderr, func(string) string { return "" })
	if err != nil {
		t.Fatalf("launchNodesProxyExecWithStreams: %v", err)
	}
	if factory.connection.Token != "token-allowed-two" {
		t.Fatalf("selected token = %q, want second qualifying token", factory.connection.Token)
	}
	if client.execs != 1 {
		t.Fatalf("Exec calls = %d, want 1", client.execs)
	}
	if fmt.Sprint(client.execArgv) != "[cat /etc/shadow]" {
		t.Fatalf("exec argv = %#v, want [cat /etc/shadow]", client.execArgv)
	}
}

func TestLaunchNodesProxyExecUncheckedRequiresAcknowledgement(t *testing.T) {
	reviewer := &fakeNodesProxyReviewer{calls: make(map[string]int)}
	client := &fakeNodesProxyKubelet{targets: []nodesproxyexec.Target{{
		NodeName: "worker-1", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: nodesproxyexec.ContainerRegular,
	}}}
	factory := &fakeNodesProxyFactory{client: client}
	installNodesProxyFakes(t, reviewer, factory)

	input := "worker-1\n0\nwrong-ack\n"
	var stdout, stderr strings.Builder
	err := launchNodesProxyExecWithStreams(context.Background(), ServerInfo{UseAuthCanI: false}, []ServiceAccount{{Name: "unchecked", Token: "unchecked-secret"}}, strings.NewReader(input), &stdout, &stderr, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "unchecked credential selection cancelled") {
		t.Fatalf("error = %v", err)
	}
	if client.probe != 0 || client.execs != 0 {
		t.Fatalf("direct kubelet was reached: probe=%d exec=%d", client.probe, client.execs)
	}
	if len(reviewer.calls) != 0 {
		t.Fatalf("disabled authorization made review calls: %#v", reviewer.calls)
	}
	if strings.Contains(stdout.String()+stderr.String(), "unchecked-secret") {
		t.Fatal("output leaked unchecked credential")
	}
}

func TestLaunchNodesProxyExecNoStoredTokensStopsBeforePrompts(t *testing.T) {
	var stdout, stderr strings.Builder
	err := launchNodesProxyExecWithStreams(context.Background(), ServerInfo{}, nil, strings.NewReader("ignored\n"), &stdout, &stderr, func(string) string { return "worker-1" })
	if !errors.Is(err, nodesproxyexec.ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestReadNodesProxyLinePreservesSubsequentResponses(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("first\nsecond value\nthird\n"))
	var output strings.Builder
	for index, want := range []string{"first", "second value", "third"} {
		got, err := readNodesProxyLine(reader, &output, fmt.Sprintf("prompt-%d: ", index))
		if err != nil {
			t.Fatalf("read %d: %v", index, err)
		}
		if got != want {
			t.Fatalf("read %d = %q, want %q", index, got, want)
		}
	}
}

func TestParseNodesProxyCommand(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantError string
	}{
		{name: "words", input: "cat /etc/shadow", want: []string{"cat", "/etc/shadow"}},
		{name: "quotes and escapes", input: `printf "%s %s" 'two words' escaped\ value ""`, want: []string{"printf", "%s %s", "two words", "escaped value", ""}},
		{name: "unterminated quote", input: `echo "unfinished`, wantError: "unterminated quote"},
		{name: "trailing escape", input: `echo trailing\`, wantError: "trailing escape"},
		{name: "empty", input: "   ", wantError: "command is empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseNodesProxyCommand(test.input)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNodesProxyCommand: %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("argv = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestReadKubeletTLSOptionsDefaultsToInsecure(t *testing.T) {
	tests := []struct {
		name       string
		connection ServerInfo
		input      string
		want       kube.KubeletTLSOptions
		wantLabel  string
		wantPrompt string
	}{
		{
			name:       "insecure default despite active CA data",
			connection: ServerInfo{CACertData: "trusted-ca"},
			input:      "\n",
			want:       kube.KubeletTLSOptions{Insecure: true},
			wantLabel:  "insecure",
			wantPrompt: "Kubelet TLS mode [ca-data/ca-file/insecure] [insecure]: ",
		},
		{
			name:       "explicit active CA data",
			connection: ServerInfo{CACertData: "trusted-ca"},
			input:      "ca-data\nkubelet.internal\n",
			want:       kube.KubeletTLSOptions{CAData: []byte("trusted-ca"), ServerName: "kubelet.internal"},
			wantLabel:  "verified",
		},
		{
			name:       "active CA file default",
			connection: ServerInfo{CAPath: "/var/run/secrets/ca.crt"},
			input:      "ca-file\n\nkubelet.internal\n",
			want:       kube.KubeletTLSOptions{CAFile: "/var/run/secrets/ca.crt", ServerName: "kubelet.internal"},
			wantLabel:  "verified",
		},
		{
			name:      "explicit insecure",
			input:     "insecure\n",
			want:      kube.KubeletTLSOptions{Insecure: true},
			wantLabel: "insecure",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			got, label, err := readKubeletTLSOptions(bufio.NewReader(strings.NewReader(test.input)), &stdout, &stderr, test.connection)
			if err != nil {
				t.Fatalf("readKubeletTLSOptions: %v", err)
			}
			if string(got.CAData) != string(test.want.CAData) || got.CAFile != test.want.CAFile || got.ServerName != test.want.ServerName || got.Insecure != test.want.Insecure {
				t.Fatalf("TLS options = %#v, want %#v", got, test.want)
			}
			if label != test.wantLabel {
				t.Fatalf("label = %q, want %q", label, test.wantLabel)
			}
			if test.wantPrompt != "" && !strings.Contains(stdout.String(), test.wantPrompt) {
				t.Fatalf("stdout = %q, want prompt %q", stdout.String(), test.wantPrompt)
			}
			if strings.Contains(stdout.String()+stderr.String(), "trusted-ca") {
				t.Fatal("TLS prompts leaked CA data")
			}
		})
	}
}
