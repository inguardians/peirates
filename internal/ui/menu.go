package ui

import "fmt"

// PrintMenu displays the full or minimal interactive command menu.
func PrintMenu(full bool) {
	if full {
		printMenuClassic()
		return
	}
	printMenuMinimal()
}

func printMenuMinimal() {
	println(`---------------------------------------------------------------------
Menu |
-----+
[sa-menu]                             List, maintain, or switch service account contexts (try: listsa *, switchsa, get-sa)
[ns-menu]                             List and/or change namespaces (try: listns, switchns)
[cert-menu]                           Switch certificate-based authentication (kubelet or manually-entered)

[ kubectl ________________________ ]  Run a kubectl command using the current authorization context
[ kubectl-try-all-until-success __ ]  Run a kubectl command using EVERY authorization context until one works
[ kubectl-try-all ________________ ]  Run a kubectl command using EVERY authorization context

[ set-auth-can-i ]                    Deactivate "auth can-i" checking before attempting actions 
[ curl ]                              Make an HTTP request (GET or POST) to a user-specified URL 
[ tcpscan ]                           Run a simple all-ports TCP port scan against an IP address 
[ cd , pwd , ls , cat ]               Manipulate the filesystem via Golang-native commands
[ shell <command> ]                   Run a shell command 

[ full ]                              Switch to full (classic menu) with a longer list of commands
[ outputfile ]                        Write all kubectl output to a file **ALPHA** [outputfile [filename]]
[ exit ]                              Exit Peirates 
---------------------------------------------------------------------`)
	fmt.Printf("\nPeirates:># ")
}

func printMenuClassic() {
	println(`---------------------------------------------------------------------
Namespaces, Service Accounts and Roles |
---------------------------------------+
[1] List, maintain, or switch service account contexts [sa-menu]  (try: list-sa *, switch-sa, get-sa)
[2] List and/or change namespaces [ns-menu] (try: list-ns, switch-ns, get-ns)
[3] Get list of pods in current namespace [list-pods, get-pods] 
[4] Get complete info on all pods (json) [dump-pod-info] 
[5] Check all pods for volume mounts [find-volume-mounts] 
[6] Enter AWS IAM credentials manually [aws-enter-credentials]
[7] Attempt to Assume a Different AWS Role [aws-assume-role]
[8] Deactivate assumed AWS role [aws-empty-assumed-role]
[9] Switch certificate-based authentication (kubelet or manually-entered) [cert-menu]
-------------------------+
Steal Service Accounts   |
-------------------------+
[10] List secrets in this namespace from API server [list-secrets, get-secrets] 
[11] Get a service account token from a secret [secret-to-sa]
[12] Request IAM credentials from AWS Metadata API [aws-get-token] *
[13] Request IAM credentials from GCP Metadata API [gcp-get-token] *
[14] Request kube-env from GCP Metadata API [gcp-attack-kube-env] 
[15] Pull Kubernetes service account tokens from kops' GCS bucket (Google Cloud only) [gcp-attack-kops-gcs-1]  *
[16] Pull Kubernetes service account tokens from kops' S3 bucket (AWS only) [attack-kops-aws-1] 
--------------------------------+
Interrogate/Abuse Cloud API's   |
--------------------------------+
[17] List AWS S3 Buckets accessible [aws-s3-ls] 
[18] List contents of an AWS S3 Bucket [aws-s3-ls-objects]
-----------+
Compromise |
-----------+
[20] Gain a reverse rootshell on a node by launching a hostPath-mounting pod [attack-pod-hostpath-mount]
[21] Run command in one or all pods in this namespace via the API Server [exec-via-api]
[22] Run a token-dumping command in all pods via Kubelets (authorization permitting) [exec-via-kubelet]
[23] Use CVE-2024-21626 (Leaky Vessels) to get a shell on the host (runc versions <1.12) [leakyvessels] *
-------------+
Node Attacks |
-------------+
[30] Steal secrets from the node filesystem [nodefs-steal-secrets]
-----------------+
Off-Menu         +
-----------------+
[90] Run a kubectl command using the current authorization context [kubectl [arguments]]
[] Run a kubectl command using EVERY authorization context until one works [kubectl-try-all-until-success [arguments]]
[] Run a kubectl command using EVERY authorization context [kubectl-try-all [arguments]]
[91] Make an HTTP request (GET or POST) to a user-specified URL [curl]
[92] Deactivate "auth can-i" checking before attempting actions [set-auth-can-i] 
[93] Run a simple all-ports TCP port scan against an IP address [tcpscan]
[94] Enumerate services via DNS [enumerate-dns] *
[] Manipulate the filesystem [ cd , pwd , ls , cat ]
[]  Run a shell command [shell <command and arguments>]
[]  Run a Bash or Bourne shell [bash or sh]

[short] Reduce the set of visible commands in this menu
[ outputfile ] Write all kubectl output to a file **ALPHA** [outputfile [filename]]

[exit] Exit Peirates 
---------------------------------------------------------------------`)
	fmt.Printf("\nPeirates:># ")
}
