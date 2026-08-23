package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ergochat/readline"
)

func TestMainSafeModuleHelper(t *testing.T) {
	if os.Getenv("PEIRATES_MAIN_MODULE_HELPER") != "1" {
		return
	}
	if cwd := os.Getenv("PEIRATES_TEST_CWD"); cwd != "" {
		if err := os.Chdir(cwd); err != nil {
			t.Fatal(err)
		}
	}
	// Keep cloud-module smoke tests local and deterministic. These helpers are
	// used only by code paths that already support dependency injection.
	awsMetadataBaseURL = "http://127.0.0.1:1"
	gcpMetadataBaseURL = "http://127.0.0.1:1"
	gcpGetRequest = func(string, []HeaderLine, bool) (string, int, error) {
		return "", 0, errors.New("metadata unavailable in smoke test")
	}
	if os.Getenv("PEIRATES_FAKE_NAMESPACES") == "1" {
		namespaceAuthCanI = func(_ ServerInfo, _, _ string) bool { return true }
		namespaceKubectlSimple = func(_ ServerInfo, _ ...string) ([]byte, []byte, error) {
			return []byte("NAME STATUS AGE\ndefault Active 2d\n"), nil, nil
		}
	}
	if os.Getenv("PEIRATES_FAKE_PODS") == "1" {
		enumerateAuthCanI = func(_ ServerInfo, _, _ string) bool { return true }
		enumerateKubectlSimple = func(_ ServerInfo, args ...string) ([]byte, []byte, error) {
			if len(args) > 1 && args[1] == "secrets" {
				return []byte(`{"items":[{"metadata":{"name":"default-token"},"type":"kubernetes.io/service-account-token"}]}`), nil, nil
			}
			return []byte(`{"items":[{"metadata":{"name":"api"}},{"metadata":{"name":"worker"}}]}`), nil, nil
		}
	}
	os.Args = []string{"peirates", "-c", "-m", os.Getenv("PEIRATES_TEST_MODULE")}
	Main()
}

func TestMainRunsSafeModulesFromMFlag(t *testing.T) {
	for _, test := range []struct {
		module string
		want   string
	}{
		{"nodefs-secrets-list", "Item not yet implemented"}, {"31", "Item not yet implemented"},
		{"aws-empty-assumed-role", "Attempting menu option"}, {"8", "Attempting menu option"},
		{"exit", "Attempting menu option"}, {"quit", "Attempting menu option"},
		{"kubectl version", "certificate authority path not defined"},
		{"kubectl-try-all get pods", "Trying the command as every service account."},
		{"kubectl-try-all-until-success get pods", "until we find one that works."},
		{"curl -d invalid", "Could not create request."}, {"curl -X", "Could not create request."},
		{"full", "Attempting menu option"}, {"help", "Attempting menu option"},
		{"short", "Attempting menu option"}, {"minimal", "Attempting menu option"},
		{"shell echo module-shell-output", "module-shell-output"},
	} {
		t.Run(test.module, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
			cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE="+test.module)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Main -m %s failed: %v\n%s", test.module, err, output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("Main -m %q output did not contain %q:\n%s", test.module, test.want, output)
			}
		})
	}
}

func TestMainRunsNonInteractiveFilesystemModules(t *testing.T) {
	dir := t.TempDir()
	file := "module-test.txt"
	if err := os.WriteFile(dir+string(os.PathSeparator)+file, []byte("module file contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		module string
		want   string
	}{
		{"pwd", dir},
		{"ls", file},
		{"cat " + file, "module file contents"},
		{"cd " + dir, dir},
		{"outputfile", "deactivating output to file"},
		{"outputfile output.log", "Output file set to: output.log"},
		{"outputfile two words", "must not contain spaces"},
	} {
		t.Run(test.module, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
			cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE="+test.module, "PEIRATES_TEST_CWD="+dir)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Main -m %q failed: %v\n%s", test.module, err, output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("Main -m %q output did not contain %q:\n%s", test.module, test.want, output)
			}
		})
	}
}

func TestMainListsNamespacesWithSuccessfulKubernetesResponse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
	cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE=list-ns", "PEIRATES_FAKE_NAMESPACES=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Main -m list-ns failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "default") {
		t.Fatalf("namespace output missing default namespace:\n%s", output)
	}
}

func TestMainListsPodsWithSuccessfulKubernetesResponse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
	cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE=get-pods", "PEIRATES_FAKE_PODS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Main -m get-pods failed: %v\n%s", err, output)
	}
	for _, pod := range []string{"api", "worker"} {
		if !strings.Contains(string(output), pod) {
			t.Fatalf("pod output missing %q:\n%s", pod, output)
		}
	}
}

func TestMainListsSecretsWithSuccessfulKubernetesResponse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
	cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE=list-secrets", "PEIRATES_FAKE_PODS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Main -m list-secrets failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "default-token") {
		t.Fatalf("secret output missing default token:\n%s", output)
	}
}

func TestMainDumpsPodInfoWithSuccessfulKubernetesResponse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
	cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE=dump-pod-info", "PEIRATES_FAKE_PODS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Main -m dump-pod-info failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Retrieving details for all pods was successful") {
		t.Fatalf("pod info success output missing:\n%s", output)
	}
}

func TestMainRunsMenuModulesWithoutTerminalInput(t *testing.T) {
	for _, module := range []string{
		"sa-menu", "list-sa", "switch-sa", "decode-jwt", "ns-menu", "list-ns", "switch-ns",
		"cert-menu", "set-auth-can-i", "curl", "exec-via-api",
		"aws-enter-credentials", "aws-assume-role", "aws-s3-ls", "aws-s3-ls-objects",
		"inject-and-exec", "attack-pod-hostpath-mount", "nodefs-steal-secrets", "bash", "sh",
		"get-pods", "dump-pod-info", "find-volume-mounts", "list-secrets", "secret-to-sa",
		"exec-via-kubelet", "leakyvessels", "tcpscan", "enumerate-dns",
		"aws-get-token", "attack-aws-kops-1", "gcp-attack-kops-1", "gcp-get-token", "gcp-attack-kube-env",
	} {
		t.Run(module, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
			cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE="+module)
			output, err := cmd.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("Main -m %q waited for terminal input:\n%s", module, output)
			}
			if err != nil {
				t.Fatalf("Main -m %q failed: %v\n%s", module, err, output)
			}
		})
	}
}

// TestMainMenuCompletionIncludesEveryCanonicalModule protects the command-line
// module surface: every canonical command advertised by the full menu must be
// reachable through `peirates -m <command>` as well as interactive completion.
func TestMainMenuCompletionIncludesEveryCanonicalModule(t *testing.T) {
	completer := setUpCompletionMainMenu()
	actual := make([]string, 0, len(completer.Children))
	for _, child := range completer.Children {
		actual = append(actual, strings.TrimSpace(child.Name))
	}
	sort.Strings(actual)

	want := []string{
		"sa-menu", "list-sa", "switch-sa", "get-sa", "decode-jwt",
		"ns-menu", "list-ns", "switch-ns", "get-pods", "list-pods",
		"dump-pod-info", "find-volume-mounts", "enter-aws-credentials",
		"aws-enter-credentials", "aws-assume-role", "aws-empty-assumed-role", "cert-menu",
		"list-secrets", "get-secrets", "secret-to-sa", "get-aws-token",
		"aws-get-token", "get-gcp-token", "gcp-get-token", "attack-kube-env-gcp",
		"gcp-attack-kube-env", "attack-kops-gcs-1", "gcp-attack-kops-1",
		"attack-kops-aws-1", "aws-attack-kops-1", "aws-s3-ls",
		"aws-s3-ls-objects", "attack-pod-hostpath-mount", "exec-via-api",
		"exec-via-kubelet", "leakyvessels", "nodefs-steal-secrets", "nodefs-secrets-list",
		"inject-and-exec",
		"kubectl", "kubectl-try-all", "kubectl-try-all-until-success", "curl",
		"set-auth-can-i", "tcpscan", "enumerate-dns", "cd", "pwd", "ls", "cat",
		"shell", "short", "full", "outputfile", "exit",
	}
	for _, command := range want {
		index := sort.SearchStrings(actual, command)
		if index == len(actual) || actual[index] != command {
			t.Errorf("canonical -m command %q is absent from main-menu completion", command)
		}
	}
}

func TestSubmenuCompletionCommands(t *testing.T) {
	tests := []struct {
		name string
		got  *readline.PrefixCompleter
		want []string
	}{
		{"namespace", setUpCompletionNsMenu(), []string{"list", "switch"}},
		{"service account", setUpCompletionSaMenu(), []string{"listsa", "switchsa", "add", "export", "import", "decode", "display"}},
		{"certificate", setUpCompletionCertMenu(), []string{"list", "switch"}},
		{"auth can-i", setUpCompletionAuthCanIMenu(), []string{"true", "false", "exit"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.got.Children) != len(test.want) {
				t.Fatalf("completion items = %d, want %d", len(test.got.Children), len(test.want))
			}
			for i, want := range test.want {
				if got := strings.TrimSpace(test.got.Children[i].Name); got != want {
					t.Errorf("item %d = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestCanonicalModuleCommandAliases(t *testing.T) {
	for alias, want := range moduleCommandAliases {
		if got := canonicalModuleCommand(alias); got != want {
			t.Errorf("canonicalModuleCommand(%q) = %q, want %q", alias, got, want)
		}
	}
	if got := canonicalModuleCommand("not-a-module"); got != "not-a-module" {
		t.Fatalf("unknown module = %q", got)
	}
}

func TestCanonicalModuleCommandsRemainUnchanged(t *testing.T) {
	for _, command := range []string{
		"kubectl", "switch-sa", "list-sa", "sa-menu", "decode-jwt", "list-ns", "switch-ns", "ns-menu",
		"get-pods", "dump-pod-info", "aws-enter-credentials", "aws-assume-role", "aws-empty-assumed-role",
		"cert-menu", "list-secrets", "secret-to-sa", "find-volume-mounts", "attack-pod-hostpath-mount",
		"aws-get-token", "gcp-get-token", "gcp-attack-kube-env", "gcp-attack-kops-1", "aws-attack-kops-1",
		"aws-s3-ls", "aws-s3-ls-objects", "exec-via-api", "exec-via-kubelet", "leakyvessels",
		"nodefs-steal-secrets", "nodefs-secrets-list", "inject-and-exec", "curl", "set-auth-can-i", "tcpscan",
		"enumerate-dns", "bash", "sh", "full", "short", "exit", "quit",
	} {
		if got := canonicalModuleCommand(command); got != command {
			t.Errorf("canonical command %q was rewritten to %q", command, got)
		}
	}
}
