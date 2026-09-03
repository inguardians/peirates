package ui

import "github.com/ergochat/readline"

var mainMenuCommands = []string{
	"sa-menu", "switch-sa", "sa-switch", "list-sa", "sa-list", "get-sa", "list-sa", "decode-jwt",
	"ns-menu", "list-ns", "switch-ns", "get-pods", "list-pods", "dump-pod-info", "find-volume-mounts",
	"enter-aws-credentials", "aws-enter-credentials", "aws-assume-role", "aws-empty-assumed-role", "cert-menu",
	"list-secrets", "get-secrets", "secret-to-sa", "get-aws-token", "aws-get-token", "get-gcp-token", "gcp-get-token",
	"attack-kube-env-gcp", "gcp-attack-kube-env", "attack-kops-gcs-1", "gcp-attack-kops-1", "attack-kops-aws-1",
	"aws-attack-kops-1", "aws-s3-ls", "aws-s3-ls-objects", "attack-pod-hostpath-mount", "exec-via-api",
	"exec-via-kubelet", "leakyvessels", "hostpid-breakout", "nodefs-steal-secrets", "nodefs-secrets-list", "inject-and-exec", "kubectl",
	"kubectl-try-all-until-success", "kubectl-try-all", "curl", "set-auth-can-i", "tcpscan", "enumerate-dns",
	"cd", "pwd", "ls", "cat", "shell", "short", "full", "outputfile", "exit",
}

// SetUpCompletionMainMenu creates completion entries in their historical order.
func SetUpCompletionMainMenu() *readline.PrefixCompleter {
	items := make([]*readline.PrefixCompleter, 0, len(mainMenuCommands))
	for _, command := range mainMenuCommands {
		items = append(items, readline.PcItem(command))
	}
	return readline.NewPrefixCompleter(items...)
}
