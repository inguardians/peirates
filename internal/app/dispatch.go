package app

// CanonicalCommand resolves every historical module alias to its handler name.
func CanonicalCommand(input string) string {
	if canonical, ok := commandAliases[input]; ok {
		return canonical
	}
	return input
}

var commandAliases = map[string]string{
	"0": "kubectl", "90": "kubectl",
	"switchsa": "switch-sa", "saswitch": "switch-sa", "sa-switch": "switch-sa",
	"listsa": "list-sa", "salist": "list-sa", "sa-list": "list-sa", "get-sa": "list-sa",
	"1": "sa-menu", "service-account-menu": "sa-menu", "sa": "sa-menu", "service-account": "sa-menu",
	"decode-sa": "decode-jwt", "decodejwt": "decode-jwt", "decodesa": "decode-jwt",
	"listns": "list-ns", "nslist": "list-ns", "ns-list": "list-ns", "get-ns": "list-ns", "getns": "list-ns",
	"switchns": "switch-ns", "nsswitch": "switch-ns", "ns-switch": "switch-ns",
	"2": "ns-menu", "namespace-menu": "ns-menu", "ns": "ns-menu", "namespace": "ns-menu",
	"3": "get-pods", "list-pods": "get-pods", "4": "dump-pod-info", "dump-podinfo": "dump-pod-info",
	"6": "aws-enter-credentials", "enter-aws-credentials": "aws-enter-credentials", "aws-creds": "aws-enter-credentials",
	"7": "aws-assume-role", "8": "aws-empty-assumed-role", "empty-aws-assumed-role": "aws-empty-assumed-role",
	"9": "cert-menu", "10": "list-secrets", "get-secrets": "list-secrets", "11": "secret-to-sa", "get-secret": "secret-to-sa",
	"5": "find-volume-mounts", "find-mounts": "find-volume-mounts",
	"20": "attack-pod-hostpath-mount", "attack-hostpath-mount": "attack-pod-hostpath-mount", "attack-pod-mount": "attack-pod-hostpath-mount", "attack-hostmount-pod": "attack-pod-hostpath-mount", "attack-mount-pod": "attack-pod-hostpath-mount",
	"12": "aws-get-token", "get-aws-token": "aws-get-token", "13": "gcp-get-token", "get-gcp-token": "gcp-get-token",
	"14": "gcp-attack-kube-env", "attack-kube-env-gcp": "gcp-attack-kube-env", "15": "gcp-attack-kops-1", "attack-kops-gcs-1": "gcp-attack-kops-1",
	"16": "aws-attack-kops-1", "attack-aws-kops-1": "aws-attack-kops-1", "17": "aws-s3-ls", "aws-ls-s3": "aws-s3-ls", "ls-s3": "aws-s3-ls", "s3-ls": "aws-s3-ls",
	"18": "aws-s3-ls-objects", "aws-s3-list-objects": "aws-s3-ls-objects", "aws-s3-list-bucket": "aws-s3-ls-objects",
	"21": "exec-via-api", "22": "exec-via-kubelet", "exec-via-kubelets": "exec-via-kubelet", "23": "leakyvessels", "cve-2024-21626": "leakyvessels",
	"30": "nodefs-steal-secrets", "steal-nodefs-secrets": "nodefs-steal-secrets", "31": "nodefs-secrets-list", "list-nodefs-secrets": "nodefs-secrets-list",
	"89": "inject-and-exec", "91": "curl", "92": "set-auth-can-i", "93": "tcpscan", "tcp scan": "tcpscan", "portscan": "tcpscan", "port scan": "tcpscan",
	"94": "enumerate-dns", "help": "full", "minimal": "short",
}
