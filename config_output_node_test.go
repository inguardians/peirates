package peirates

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stubNamespaces(t *testing.T, allowed bool, output string, outputErr error) {
	t.Helper()
	originalAuth, originalKubectl := namespaceAuthCanI, namespaceKubectlSimple
	namespaceAuthCanI = func(_ ServerInfo, verb, resource string) bool {
		if verb != "get" || resource != "namespaces" {
			t.Errorf("unexpected auth check %s %s", verb, resource)
		}
		return allowed
	}
	namespaceKubectlSimple = func(_ ServerInfo, args ...string) ([]byte, []byte, error) {
		if len(args) != 2 || args[0] != "get" || args[1] != "namespaces" {
			t.Errorf("unexpected kubectl arguments %#v", args)
		}
		return []byte(output), nil, outputErr
	}
	t.Cleanup(func() { namespaceAuthCanI, namespaceKubectlSimple = originalAuth, originalKubectl })
}

func TestFindFlagValue(t *testing.T) {
	args := []string{"kubelet", "--config=/etc/kubelet.conf", "--v=2"}
	if got := findFlagValue(args, "--config"); got != "/etc/kubelet.conf" {
		t.Fatalf("findFlagValue() = %q", got)
	}
	if got := findFlagValue(args, "--missing"); got != "" {
		t.Fatalf("missing flag = %q", got)
	}
	if got := findFlagValue([]string{"--config-file=/wrong"}, "--config"); got != "" {
		t.Fatalf("prefix-only match = %q", got)
	}
}

func TestGetPodName(t *testing.T) {
	root := t.TempDir() + string(os.PathSeparator)
	podID := "pod-id"
	dir := filepath.Join(root, podID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "# comment\n127.0.0.1 localhost\n10.1.2.3 target-pod\n"
	if err := os.WriteFile(filepath.Join(dir, "etc-hosts"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := getPodName(root, podID); got != "target-pod" {
		t.Fatalf("getPodName() = %q", got)
	}
	if got := getPodName(root, "missing"); got != "<not detected - ne>" {
		t.Fatalf("missing pod = %q", got)
	}
}

func TestAddNewSecretFromPodViaNodeFS(t *testing.T) {
	var secrets []SecretFromPodViaNodeFS
	if !AddNewSecretFromPodViaNodeFS(" db-password ", "/tmp/secret", "pod-a", &secrets) {
		t.Fatal("expected first secret to be added")
	}
	if AddNewSecretFromPodViaNodeFS("db-password", "/other", "pod-b", &secrets) {
		t.Fatal("expected trimmed duplicate to be rejected")
	}
	if len(secrets) != 1 || secrets[0].DiscoveryMethod != "gathered from node filesystem" || secrets[0].DiscoveryTime.IsZero() {
		t.Fatalf("unexpected secret: %#v", secrets)
	}
}

func TestOutputToUserWritesRequestedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.log")
	outputToUser("test output\n", true, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "test output\n" {
		t.Fatalf("log contents = %q", data)
	}
}

func TestParseOptionsNormalizesConnection(t *testing.T) {
	originalArgs, originalVerbose := os.Args, Verbose
	t.Cleanup(func() { os.Args, Verbose = originalArgs, originalVerbose })
	os.Args = []string{"peirates", "-u", " api.example:6443/ ", "-t", "token", "-c", "-v"}
	opts := CommandLineOptions{connectionConfig: &ServerInfo{}}
	parseOptions(&opts)
	if opts.connectionConfig.APIServer != "https://api.example:6443" || opts.connectionConfig.Token != "token" || !opts.noCloudDetection || !opts.verbose || !Verbose {
		t.Fatalf("unexpected parsed options: %#v", opts)
	}
}

func TestGetNamespaces(t *testing.T) {
	stubNamespaces(t, true, "NAME STATUS AGE\ndefault Active 2d\nkube-system Active 2d\nterminating Terminating 1h\npartial\n", nil)
	got, err := GetNamespaces(ServerInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"default", "kube-system"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("GetNamespaces() = %#v, want %#v", got, want)
	}
}

func TestGetNamespacesErrors(t *testing.T) {
	stubNamespaces(t, false, "", nil)
	if _, err := GetNamespaces(ServerInfo{}); err == nil {
		t.Fatal("expected permission error")
	}

	stubNamespaces(t, true, "", errors.New("kubectl failed"))
	if _, err := GetNamespaces(ServerInfo{}); err == nil {
		t.Fatal("expected kubectl error")
	}
}

func TestGetCmdLineRejectsMissingProcess(t *testing.T) {
	if _, err := getCmdLine("definitely-not-a-pid"); err == nil {
		t.Fatal("getCmdLine succeeded for a missing process")
	}
}
