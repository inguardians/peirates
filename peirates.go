package peirates

// Peirates - an Attack tool for Kubernetes clusters

import (
	"errors"
	"fmt"
	"io"

	"os"
	"os/exec"
	"strings"

	"github.com/ergochat/readline"
)

// Verbosity mode - if set to true, DEBUG messages will be printed to STDOUT.
var Verbose bool

// If this option is on, kubectl commands will be preceded with an auth can-i
// check. Note that this only checks against RBAC, such that admission
// controllers can still block an action that RBAC permits.
var UseAuthCanI bool = true

//------------------------------------------------------------------------------------------------------------------------------------------------

// Main starts Peirates[]
func Main() {
	// Peirates version string
	var version = "1.1.27a"

	var err error

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionMainMenu()

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

	// Output file logging - new stealth feature
	var logToFile = false
	var outputFileName string

	// Struct for some functions
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

	// FEATURE to Write:  store discovered namespaces, using multiple methods for gathering them.
	// namespaces := []string

	// print the banner, so that any node credentials pulled are not out of place.
	printBanner(interactive, version)

	// Add the kubelet kubeconfig and authentication information if available.
	err = checkForNodeCredentials(&clientCertificates, &connectionString)
	if err != nil {
		println("Problem with credentials: %v", err)
	}
	// If there are client certs, but no service accounts, switch to the first client cert
	if (len(serviceAccounts) == 0) && (len(clientCertificates) > 0) {
		assignAuthenticationCertificateAndKeyToConnection(clientCertificates[0], &connectionString)
	}

	// Add the service account tokens for any pods found in /var/lib/kubelet/pods/.
	gatherPodCredentials(&serviceAccounts, interactive, false)

	// If there are no client certs, and if our current context does not name a service account, switch
	// to the first service account.
	if (len(clientCertificates) == 0) && (len(serviceAccounts) > 0) {
		assignServiceAccountToConnection(serviceAccounts[0], &connectionString)
	}

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

		l, err := readline.NewEx(&readline.Config{
			Prompt:          "\033[31m»\033[0m ",
			HistoryFile:     "/tmp/peirates.history",
			AutoComplete:    completer,
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",

			HistorySearchFold: true,
			// FuncFilterInputRune: filterInput,
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()
		// l.CaptureExitSignal()

		err = errors.New("empty")

		if interactive {
			printMenu(fullMenu)

			// input, err = ReadLineStripWhitespace()
			line, err := l.Readline()
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					break
				} else {
					continue
				}
			} else if err == io.EOF {
				break
			}
			input = strings.TrimSpace(line)

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
			kubectlOutputString := string(kubectlOutput)
			outputToUser(kubectlOutputString, logToFile, outputFileName)

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

			_, _, err := attemptEveryAccount(false, &connectionString, &serviceAccounts, &clientCertificates, logToFile, outputFileName, arguments...)

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

			_, _, err := attemptEveryAccount(true, &connectionString, &serviceAccounts, &clientCertificates, logToFile, outputFileName, arguments...)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] Could not perform action or received an error on: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(interactive)
			continue
		}

		//
		// Handle built-in filesystem commands before the switch menu
		//

		const pwd = "pwd"
		if input == pwd {
			// Print the current working directory
			cwd, error := getCurrentDirectory()
			if error != nil {
				println("Error getting current directory: " + error.Error())
				continue
			}
			println(cwd)
			pauseToHitEnter(interactive)
			continue
		}

		const cdSpace = "cd "
		if strings.HasPrefix(input, cdSpace) {

			// Trim off the newline - should we do this for all input anyway?
			input = strings.TrimSuffix(input, "\n")
			// Trim off the cd, then grab the argument.
			// This will fail if there are spaces in the directory name - TODO: improve this.
			argumentsLine := strings.TrimPrefix(input, cdSpace)
			arguments := strings.Fields(argumentsLine)
			directory := arguments[0]
			// remove the cd, then try to change to that directory
			changeDirectory(directory)

			// Get the new directory and print its name
			cwd, error := getCurrentDirectory()
			if error != nil {
				println("Error getting current directory: " + error.Error())
				continue
			}
			println(cwd)

			pauseToHitEnter(interactive)
			continue
		}

		// cat to display files
		const catSpace = "cat "
		if strings.HasPrefix(input, catSpace) {
			// Trim off the newline - should we do this for all input anyway?
			input = strings.TrimSuffix(input, "\n")
			// remove the cat, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, catSpace)
			spaceDelimitedSet := strings.Fields(argumentsLine)
			for _, file := range spaceDelimitedSet {
				err := displayFile(file)
				if err != nil {
					println("Error displaying file: " + file + " due to " + err.Error())
				}
			}
			pauseToHitEnter(interactive)
			continue
		}

		// ls to list directories - treat this differently if it has no arguments

		const lsSpace = "ls "
		if strings.HasPrefix(input, lsSpace) {
			// Trim off the newline - should we do this for all input anyway?
			input = strings.TrimSuffix(input, "\n")
			// remove the ls, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, lsSpace)
			spaceDelimitedSet := strings.Fields(argumentsLine)
			for _, dir := range spaceDelimitedSet {
				// Check for flags - reject them
				if strings.HasPrefix(dir, "-") {
					println("ERROR: Flags are not supported in this version of ls.")
					continue
				}
				err := listDirectory(dir)
				if err != nil {
					println("Error listing directory: " + dir + " due to " + err.Error())
				}
			}
			pauseToHitEnter(interactive)
			continue
		}

		// ls with no arguments means list the current directory
		const ls = "ls"
		if strings.HasPrefix(input, ls) {
			error := listDirectory(".")
			if error != nil {
				println("Error listing directory: " + error.Error())
			}
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
				outputToUser(string(out), logToFile, outputFileName)

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
				pauseToHitEnter(interactive)
				continue
			}
			responseBody, err := DoHTTPRequestAndGetBody(request, https, ignoreTLSErrors, caCertPath)
			if err != nil {
				println("Request produced an error.")
			}

			outputToUser(string(responseBody), logToFile, outputFileName)

			pauseToHitEnter(interactive)
			continue
		}

		// Handle outputfile commands before the switch menu

		// Activate via "outputfile <filename>"
		const outputFile = "outputfile "
		if strings.HasPrefix(input, outputFile) {
			// remove the outputfile prefix, then get a filename from the rest
			input = strings.TrimPrefix(input, outputFile)

			// confirm that outputfile only has one argument.
			if strings.Contains(input, " ") {
				println("Output file name must not contain spaces.")
				pauseToHitEnter(interactive)
				continue
			}

			// Set the output file to that argument and set logToFile to true.
			logToFile = true
			outputFileName = input
			println("Output file set to: " + outputFileName)

			// If there is no argument, set logToFile to false.
			pauseToHitEnter(interactive)
			continue
		}

		// Deactivate via "outputfile"
		const outputFileBare = "outputfile"
		if strings.HasPrefix(input, outputFileBare) {
			println("Output file name is empty - deactivating output to file.")
			logToFile = false
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
			_ = kubectl_interactive(connectionString, logToFile, outputFileName)

		//	[1] List, maintain, or switch service account contexts [sa-menu]  (try: list-sa *, switch-sa, get-sa)
		case "switchsa", "saswitch", "switch-sa", "sa-switch":
			switchServiceAccounts(serviceAccounts, &connectionString, logToFile, outputFileName)
		case "listsa", "list-sa", "salist", "sa-list", "get-sa":
			listServiceAccounts(serviceAccounts, connectionString, logToFile, outputFileName)
		case "1", "sa-menu", "service-account-menu", "sa", "service-account":
			saMenu(&serviceAccounts, &connectionString, interactive, logToFile, outputFileName)
		case "decode-jwt", "decode-sa", "decodejwt", "decodesa":
			decodeTokenInteractive(serviceAccounts, &connectionString, logToFile, outputFileName, interactive)

		// [2] List and/or change namespaces [ns-menu] (try: list-ns, switch-ns, get-ns)
		case "list-ns", "listns", "nslist", "ns-list", "get-ns", "getns":
			listNamespaces(connectionString)
		case "switch-ns", "switchns", "nsswitch", "ns-switch":
			menuSwitchNamespaces(&connectionString)
		case "2", "ns-menu", "namespace-menu", "ns", "namespace":
			interactiveNSMenu(&connectionString)

		// [3] Get list of pods
		case "3", "get-pods", "list-pods":
			printListOfPods(connectionString)

		//[4] Get complete info on all pods (json)
		case "4", "dump-podinfo", "dump-pod-info":
			GetPodsInfo(connectionString, &podInfo)

		//	[6] Enter AWS IAM credentials manually [enter-aws-credentials]
		case "6", "enter-aws-credentials", "aws-creds":
			credentials, err := EnterIamCredentialsForAWS()
			if err != nil {
				println("[-] Error entering AWS credentials: ", err)
				break
			}

			awsCredentials = credentials
			println(" New AWS credentials are: \n")
			DisplayAWSIAMCredentials(awsCredentials)

		// [7] Attempt to Assume a Different AWS Role [aws-assume-role]
		case "7", "aws-assume-role":
			assumeAWSrole(awsCredentials, &assumedAWSrole, interactive)

		// [8] Deactivate assumed AWS role [aws-empty-assumed-role]
		case "8", "aws-empty-assumed-role", "empty-aws-assumed-role":
			assumedAWSrole.AccessKeyId = ""
			assumedAWSrole.accountName = ""

		// [9] Switch authentication contexts: certificate-based authentication (kubelet, kubeproxy, manually-entered) [cert-menu]
		case "9", "cert-menu":
			certMenu(&clientCertificates, &connectionString, interactive)

		//	[10] List secrets in this namespace from API server [list-secrets, get-secrets]
		case "10", "list-secrets", "get-secrets":
			listSecrets(&connectionString)

		// [11] Get a service account token from a secret
		case "11", "get-secret", "secret-to-sa":
			getServiceAccountTokenFromSecret(connectionString, &serviceAccounts, interactive)

		// [5] Check all pods for volume mounts
		case "5", "find-volume-mounts", "find-mounts":
			findVolumeMounts(connectionString, &podInfo)

		// [20] Gain a reverse rootshell by launching a hostPath / pod
		case "20", "attack-pod-hostpath-mount", "attack-hostpath-mount", "attack-pod-mount", "attack-hostmount-pod", "attack-mount-pod":
			attackHostPathMount(connectionString, interactive)

		// [12] Request IAM credentials from AWS Metadata API [AWS only]
		case "12", "get-aws-token":
			result, err := getAWSToken(interactive)
			if err != nil {
				awsCredentials = result
			}

		// [13] Request IAM credentials from GCP Metadata API [GCP only]
		case "13", "get-gcp-token":

			getGCPToken(interactive)

		// [14] Request kube-env from GCP Metadata API [GCP only]
		case "14", "attack-kube-env-gcp":
			attackKubeEnvGCP(interactive)

		// [15] Pull Kubernetes service account tokens from Kop's bucket in GCS [GCP only]
		case "15", "attack-kops-gcs-1":
			err := KopsAttackGCP(&serviceAccounts)
			if err != nil {
				println("Kops attack failed on GCP.")
			}
			pauseToHitEnter(interactive)

		// [16] Pull Kubernetes service account tokens from kops' S3 bucket (AWS only) [attack-kops-aws-1]
		case "16":
			KopsAttackAWS(&serviceAccounts, awsCredentials, assumedAWSrole, interactive)

		case "17", "aws-s3-ls", "aws-ls-s3", "ls-s3", "s3-ls":

			// [17] List AWS S3 Buckets accessible (Auto-Refreshing Metadata API credentials) [AWS]
			awsS3ListBucketsMenu(awsCredentials, assumedAWSrole)

		case "18", "aws-s3-ls-objects", "aws-s3-list-objects", "aws-s3-list-bucket":

			// [18] List contents of an AWS S3 Bucket [AWS]
			awsS3ListBucketObjectsMenu(awsCredentials, assumedAWSrole)

		// [21] Run command in one or all pods in this namespace
		case "21", "exec-via-api":

			execInPodMenu(connectionString, interactive)

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

			injectAndExecMenu(connectionString)

		// [91] Make an HTTP request (GET or POST) to a URL of your choice [curl]
		// This is available both on the main menu line and interactively.
		// Here's the interactive.
		case "91", "curl":

			curl(interactive, logToFile, outputFileName)

		// [92] Deactivate "auth can-i" checking before attempting actions [set-auth-can-i]
		case "92", "set-auth-can-i":
			setAuthCanIMenu(&UseAuthCanI, interactive)

		// [93] Run a simple all-ports TCP port scan against an IP address [tcpscan]
		case "93", "tcpscan", "tcp scan", "portscan", "port scan":

			tcpScan(interactive)

		case "94", "enumerate-dns":
			_ = enumerateDNS()

		case "bash":
			_ = runBash()

		case "sh":
			_ = runSH()

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
