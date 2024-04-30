package peirates

import (
	"fmt"
	"os"
	"os/exec"
)

func printMenu(fullMenu bool) {
	if fullMenu {
		printMenuClassic()
	} else {
		printMenuMinimal()
	}

}

func printMenuMinimal() {
	println(`---------------------------------------------------------------------
Menu |
-----+
[sa-menu]                             List, maintain, or switch service account contexts (try: listsa *, switchsa)
[ns-menu]                             List and/or change namespaces (try: listns, switchns)
[cert-menu]                           Switch certificate-based authentication (kubelet or manually-entered)

[ kubectl ________________________ ]  Run a kubectl command using the current authorization context
[ kubectl-try-all-until-success __ ]  Run a kubectl command using EVERY authorization context until one works
[ kubectl-try-all ________________ ]  Run a kubectl command using EVERY authorization context

[ set-auth-can-i ]                    Deactivate "auth can-i" checking before attempting actions 
[ curl ]                              Make an HTTP request (GET or POST) to a user-specified URL 
[ tcpscan ]                           Run a simple all-ports TCP port scan against an IP address 
[ enumerate-dns ]                     Enumerate services via DNS  *
[ shell <command> ]                   Run a shell command 

[ full ]                              Switch to full (classic menu) with a longer list of commands
[ exit ]                              Exit Peirates 
---------------------------------------------------------------------`)
	fmt.Printf("\nPeirates:># ")
}

func printMenuClassic() {
	println(`---------------------------------------------------------------------
Namespaces, Service Accounts and Roles |
---------------------------------------+
[1] List, maintain, or switch service account contexts [sa-menu]  (try: listsa *, switchsa)
[2] List and/or change namespaces [ns-menu] (try: listns, switchns)
[3] Get list of pods in current namespace [list-pods] 
[4] Get complete info on all pods (json) [dump-pod-info] 
[5] Check all pods for volume mounts [find-volume-mounts] 
[6] Enter AWS IAM credentials manually [enter-aws-credentials]
[7] Attempt to Assume a Different AWS Role [aws-assume-role]
[8] Deactivate assumed AWS role [aws-empty-assumed-role]
[9] Switch certificate-based authentication (kubelet or manually-entered) [cert-menu]
-------------------------+
Steal Service Accounts   |
-------------------------+
[10] List secrets in this namespace from API server [list-secrets] 
[11] Get a service account token from a secret [secret-to-sa]
[12] Request IAM credentials from AWS Metadata API [get-aws-token] *
[13] Request IAM credentials from GCP Metadata API [get-gcp-token] *
[14] Request kube-env from GCP Metadata API [attack-kube-env-gcp] 
[15] Pull Kubernetes service account tokens from kops' GCS bucket (Google Cloud only) [attack-kops-gcs-1]  *
[16] Pull Kubernetes service account tokens from kops' S3 bucket (AWS only) [attack-kops-aws-1] 
--------------------------------+
Interrogate/Abuse Cloud API's   |
--------------------------------+
[17] List AWS S3 Buckets accessible (Make sure to get credentials via get-aws-token or enter manually) [aws-s3-ls] 
[18] List contents of an AWS S3 Bucket (Make sure to get credentials via get-aws-token or enter manually) [aws-s3-ls-objects]
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
[]  Run a shell command [shell <command and arguments>]

[short] Reduce the set of visible commands in this menu
[exit] Exit Peirates 
---------------------------------------------------------------------`)
	fmt.Printf("\nPeirates:># ")
}

func printBanner(interactive bool, version string) {
	println(`________________________________________
|  ___  ____ _ ____ ____ ___ ____ ____ |
|  |__] |___ | |__/ |__|  |  |___ [__  |
|  |    |___ | |  \ |  |  |  |___ ___] |
|______________________________________|`)

	if interactive {
		println(`
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,.............:,,,,,,,,,,,,,
,,,,,,,,,,...,IIIIIIIIIII+...,,,,,,,,,,,
,,,,,,,:..~IIIIIIIIIIIIIIIIII...,,,,,,,,
,,,,,,..?IIIIIII.......IIIIIIII..,,,,,,,
,,,,,..IIIIIIII...II?...?IIIIIII,..,,,,,
,,,:..IIIIIIII..:IIIIII..?IIIIIIII..,,,,
,,,..IIIIIIIII..IIIIIII...IIIIIIII7.:,,,
,,..IIIIIIIII.............IIIIIIIII..,,,
,,.=IIIIIIII...~~~~~~~~~...IIIIIIIII..,,
,..IIIIIIII...+++++++++++,..+IIIIIII..,,
,..IIIIIII...+++++++++++++:..~IIIIII..,,
,..IIIIII...++++++:++++++++=..,IIIII..,,
,..IIIII...+....,++.++++:+.++...IIII..,,
,,.+IIII...+..,+++++....+,.+...IIIII..,,
,,..IIIII...+++++++++++++++...IIIII..:,,
,,,..IIIII...+++++++++++++...IIIII7..,,,
,,,,.,IIIII...+++++++++++...?IIIII..,,,,
,,,,:..IIIII...............IIIII?..,,,,,
,,,,,,..IIIII.............IIIII..,,,,,,,
,,,,,,,,..7IIIIIIIIIIIIIIIII?...,,,,,,,,
,,,,,,,,,:...?IIIIIIIIIIII....,,,,,,,,,,
,,,,,,,,,,,,:.............,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,`)
	}
	credit := fmt.Sprintf(`________________________________________
  Peirates v%s by InGuardians and Peirates Open Source Developers
  https://www.inguardians.com/peirates
---------------------------------------------------------------------`, version)
	println(credit)
}

func clearScreen(interactive bool) {
	var err error

	pauseToHitEnter(interactive)
	c := exec.Command("clear")
	c.Stdout = os.Stdout
	err = c.Run()
	if err != nil {
		println("[-] Error running command: ", err)
	}

}

func banner(connectionString ServerInfo, detectCloud string, eth0IP string, awsCredentials AWSCredentials, assumedAWSRole AWSCredentials) {

	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	if connectionString.Token != "" {

		fmt.Println("[+] Service Account Loaded            :", connectionString.TokenName)
	}
	if connectionString.ClientCertData != "" {
		fmt.Println("[+] Client Certificate/Key Pair Loaded:", connectionString.ClientCertName)
	}

	if len(connectionString.Namespace) > 0 {
		fmt.Println("[+] Current hostname/pod name         :", name)
		fmt.Println("[+] Current namespace                 :", connectionString.Namespace)
	}

	// Print out the eth0 interface's IP address if it exists
	if len(eth0IP) > 0 {
		fmt.Println("[+] IP address for eth0               :", eth0IP)
	}
	// If cloud has been detected, print it here.
	if len(detectCloud) > 0 {
		fmt.Println("[+] Cloud provider metadata API       :", detectCloud)
	}

	// If we have an AWS role, print it here.
	if len(assumedAWSRole.AccessKeyId) > 0 {
		fmt.Println("[+] AWS IAM Credentials (assumed)     :" + assumedAWSRole.AccessKeyId + " (" + assumedAWSRole.accountName + ")\n")
	}
	if len(awsCredentials.AccessKeyId) > 0 {
		if len(awsCredentials.accountName) > 0 {
			fmt.Println("[+] AWS IAM Credentials (available)   : " + awsCredentials.AccessKeyId + " (" + awsCredentials.accountName + ")\n")
		} else {
			fmt.Println("[+] AWS IAM Credentials (available)   : " + awsCredentials.AccessKeyId + "\n")
		}
	}
}
