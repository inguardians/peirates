package app

// Peirates - an Attack tool for Kubernetes clusters

import (
	"errors"
	"fmt"
	"io"

	"os"
	"os/exec"
	"strings"

	"github.com/ergochat/readline"
	"github.com/inguardians/peirates/internal/modules"
)

// Verbose enables debug messages on standard output.
var Verbose bool

//------------------------------------------------------------------------------------------------------------------------------------------------

// Main starts Peirates[]
func Main() {
	// Peirates version string
	var version = "1.1.31"

	var err error

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionMainMenu()

	session := NewSession(ImportPodServiceAccountToken())

	// Menu detail level
	// - true: the "full" menu that Peirates had classically
	// - false: a shorter menu of options - all options still work, but not all are shown

	// AWS credentials currently in use.

	// Make room for an assumed role.

	// Create a global variable named "session.Connection" initialized to default values
	cmdOpts := CommandLineOptions{connectionConfig: &session.Connection}

	// the session.Interactive boolean tracks whether the user is running peirates in menu mode (true)
	// or in command-line mode (false)

	// Output file logging - new stealth feature

	// Struct for some functions

	// Run the option parser to initialize connectionStrings
	parseOptions(&cmdOpts)
	session.Verbose = cmdOpts.verbose

	// Skip cloud detection if -c is passed on the command line.
	var detectCloud string
	if cmdOpts.noCloudDetection {
		detectCloud = "<not checked>"
	} else {
		detectCloud = populateAndCheckCloudProviders()
	}
	session.Cloud = detectCloud

	// Check whether the -m / --module flag has been used to run just a specific module instead
	// of the menu.
	if cmdOpts.moduleToRun != "" {
		session.Interactive = false
	}

	// List of service accounts gathered so far
	if len(session.Connection.TokenName) > 0 {
		AddNewServiceAccount(session.Connection.TokenName, session.Connection.Token, "Loaded at startup", &session.ServiceAccounts)
	}

	// List of current client cert/key pairs

	// FEATURE to Write:  store discovered namespaces, using multiple methods for gathering them.
	// namespaces := []string

	// print the banner, so that any node credentials pulled are not out of place.
	printBanner(session.Interactive, version)

	// Add the kubelet kubeconfig and authentication information if available.
	err = checkForNodeCredentials(&session.ClientCertificates, &session.Connection)
	if err != nil {
		println("Problem with credentials: %v", err)
	}
	// If there are client certs, but no service accounts, switch to the first client cert
	if (len(session.ServiceAccounts) == 0) && (len(session.ClientCertificates) > 0) {
		assignAuthenticationCertificateAndKeyToConnection(session.ClientCertificates[0], &session.Connection)
	}

	// Add the service account tokens for any pods found in /var/lib/kubelet/pods/.
	gatherPodCredentials(&session.ServiceAccounts, session.Interactive, false)

	// If there are no client certs, and if our current context does not name a service account, switch
	// to the first service account.
	if (len(session.ClientCertificates) == 0) && (len(session.ServiceAccounts) > 0) {
		assignServiceAccountToConnection(session.ServiceAccounts[0], &session.Connection)
	}

	// Check environment variables - see KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	// Watch the documentation on these variables for changes:
	// https://kubernetes.io/docs/concepts/containers/container-environment-variables/

	// Read AWS credentials from environment variables if present.
	session.AWSCredentials = PullIamCredentialsFromEnvironmentVariables()

	// Collect the pod IP address if we are in a pod or on a node that has an eth0 interface.
	eth0IP, err := GetMyIPAddress("eth0")
	if err != nil {
		eth0IP = ""
	}

	moduleRegistry := newModuleRegistry(session)

	var input int
	for ok := true; ok; ok = (input != 2) {
		banner(session.Connection, detectCloud, eth0IP, session.AWSCredentials, session.AssumedAWSRole)

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

		if session.Interactive {
			printMenu(session.FullMenu)

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

			kubectlOutput, _, err := runKubectlSimple(session.Connection, arguments...)
			kubectlOutputString := string(kubectlOutput)
			outputToUser(kubectlOutputString, session.LogToFile, session.OutputFileName)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] error returned running: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
			continue
		}

		// Handle kubectl-try-all requests
		const kubectlTryAllSpace = "kubectl-try-all "
		if strings.HasPrefix(input, kubectlTryAllSpace) {

			// remove the kubectl-try-all, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlTryAllSpace)
			arguments := strings.Fields(argumentsLine)

			_, _, err := attemptEveryAccount(false, &session.Connection, &session.ServiceAccounts, &session.ClientCertificates, session.LogToFile, session.OutputFileName, arguments...)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] Could not perform action or received an error on: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
			continue
		}

		// Handle kubectl-try-all-until-success requests
		const kubectlTryAllUntilSuccessSpace = "kubectl-try-all-until-success "
		if strings.HasPrefix(input, kubectlTryAllUntilSuccessSpace) {

			// remove the kubectl-try-all, then split the rest on whitespace
			argumentsLine := strings.TrimPrefix(input, kubectlTryAllUntilSuccessSpace)
			arguments := strings.Fields(argumentsLine)

			_, _, err := attemptEveryAccount(true, &session.Connection, &session.ServiceAccounts, &session.ClientCertificates, session.LogToFile, session.OutputFileName, arguments...)

			// Note that we got an error code, in case it's the only output.
			if err != nil {
				println("[-] Could not perform action or received an error on: ", input)
			}

			// Make sure not to go into the switch-case
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
				if !session.Interactive {
					return
				}
				continue
			}
			println(cwd)
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
				if !session.Interactive {
					return
				}
				continue
			}
			println(cwd)

			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
			continue
		}

		// ls with no arguments means list the current directory
		const ls = "ls"
		if strings.HasPrefix(input, ls) {
			error := listDirectory(".")
			if error != nil {
				println("Error listing directory: " + error.Error())
			}
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
				if !session.Interactive {
					return
				}
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
				outputToUser(string(out), session.LogToFile, session.OutputFileName)

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
			if !session.Interactive {
				return
			}
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
				pauseToHitEnter(session.Interactive)
				if !session.Interactive {
					return
				}
				continue
			}
			responseBody, err := DoHTTPRequestAndGetBody(request, https, ignoreTLSErrors, caCertPath)
			if err != nil {
				println("Request produced an error.")
			}

			outputToUser(string(responseBody), session.LogToFile, session.OutputFileName)

			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
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
				pauseToHitEnter(session.Interactive)
				if !session.Interactive {
					return
				}
				continue
			}

			// Set the output file to that argument and set session.LogToFile to true.
			session.LogToFile = true
			session.OutputFileName = input
			println("Output file set to: " + session.OutputFileName)

			// If there is no argument, set session.LogToFile to false.
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
			continue
		}

		// Deactivate via "outputfile"
		const outputFileBare = "outputfile"
		if strings.HasPrefix(input, outputFileBare) {
			println("Output file name is empty - deactivating output to file.")
			session.LogToFile = false
			pauseToHitEnter(session.Interactive)
			if !session.Interactive {
				return
			}
			continue
		}

		// Handle enumerate-dns before the session.Interactive menu
		// const enumerateDNS = "enumerate-dns"
		// if strings.HasPrefix(input, enumerateDNS) {
		// 	// Run the DNS enumeration
		// 	enumerateDNS()
		// 	pauseToHitEnter(session.Interactive)
		// 	continue
		// }

		// Peirates MAIN MENU
		result, found := moduleRegistry.Run(canonicalModuleCommand(input))
		if !found {
			fmt.Println("Command unrecognized.")
		}
		if result == modules.Refresh {
			if !session.Interactive {
				return
			}
			continue
		}

		if !session.Interactive {
			os.Exit(0)
		}
		clearScreen(session.Interactive)
	}
}
