//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

type ServerInfo struct {
	APIServer      string // URL for the API server - this replaces RIPAddress and RPort
	Token          string // service account token ASCII text, if present
	TokenName      string // name of the service account token, if present
	ClientCertPath string // path to the client certificate, if present
	ClientKeyPath  string // path to the client key, if present
	ClientCertName string // name of the client cert, if present
	CAPath         string // path to Certificate Authority's certificate (public key)
	Namespace      string // namespace that this pod's service account is tied to
	UseAuthCanI    bool
}

func ParseLocalServerInfo() ServerInfo {

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
	token, errRead := ioutil.ReadFile(tokenFile)

	// Only return output if a JWT was found.
	if errRead == nil {
		configInfoVars.Token = string(token)
		fmt.Println("Read a service account token from " + tokenFile)
		// Name the token for its hostname / pod
		configInfoVars.TokenName = "Pod ns:" + configInfoVars.Namespace + ":" + os.Getenv("HOSTNAME")
	}

	// Reading namespace file and store in variable namespace
	namespace, errRead := ioutil.ReadFile(ServiceAccountPath + "namespace")
	if errRead == nil {
		configInfoVars.Namespace = string(namespace)
	}

	// Attempt to read a ca.crt file from the normal pod location - store if found.
	expectedCACertPath := ServiceAccountPath + "ca.crt"
	_, err := ioutil.ReadFile(expectedCACertPath)
	if err == nil {
		configInfoVars.CAPath = expectedCACertPath
	}

	return configInfoVars
}

func checkForNodeCredentials(clientCertificates *[]ClientCertificateKeyPair) error {

	// Paths to explore:
	// /etc/kubernetes/kubelet.conf
	// /var/lib/kubelet/kubeconfig
	// /

	// Determine if one of the paths above exists and use it to get kubelet keypairs
	kubeletKubeconfigFilePaths := make([]string, 0)

	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/etc/kubernetes/kubelet.conf")
	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/var/lib/kubelet/kubeconfig")

	// Feature request / technical debt: we should use golang's YAML parsing for this.
	for _, path := range kubeletKubeconfigFilePaths {
		// On each path, check for existence of the file.
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		file, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)

		// We're parsing this part of the file, looking for these lines:
		// users:
		// - name: system:node:nodename
		// user:
		//   client-certificate: /var/lib/kubelet/pki/kubelet-client-current.pem
		//   client-key: /var/lib/kubelet/pki/kubelet-client-current.pem

		const certificateAuthorityDataLHS = "certificate-authority-data: "
		const serverLHS = "server: "
		const clientCertConst = "client-certificate: "
		const clientKeyConst = "client-key: "
		const usersBlockStart = "users:"
		const userStart = "user:"
		const nameLineStart = "- name: "

		foundFirstUsersBlock := false
		foundFirstUser := false

		// Create empty strings for the client cert-key pair object
		clientName := "kubelet"
		clientCertPath := ""
		clientKeyPath := ""
		CACert := ""
		APIServer := ""

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if !foundFirstUsersBlock {

				if strings.HasPrefix(line, certificateAuthorityDataLHS) {
					CACertBase64Encoded := strings.TrimPrefix(line, certificateAuthorityDataLHS)

					CACertBytes, err := base64.StdEncoding.DecodeString(CACertBase64Encoded)
					if err != nil {
						println("[-] ERROR: couldn't decode")
					}
					CACert = string(CACertBytes)
				}

				if strings.HasPrefix(line, serverLHS) {
					APIServer = strings.TrimPrefix(line, serverLHS)
				}

				if strings.HasPrefix(line, usersBlockStart) {
					foundFirstUsersBlock = true
				}
				// until we have found the Users: block, we're not looking for the other patterns.
				continue
			}

			// We've found the users block, now looking for a name or a user statement.
			if !foundFirstUser {
				if strings.HasPrefix(line, userStart) {
					foundFirstUser = true
				} else if strings.HasPrefix(line, nameLineStart) {
					clientName = strings.TrimPrefix(line, nameLineStart)
				}

				// until we have found the User: block, we're not looking for user's key and cert.
				continue
			}

			if strings.Contains(line, clientCertConst) {

				clientCertPath = strings.TrimPrefix(line, clientCertConst)

				// TODO: confirm we can read the file
			} else if strings.Contains(line, clientKeyConst) {
				clientKeyPath = strings.TrimPrefix(line, clientKeyConst)
				// TODO: confirm we can read the file
			}

			// Do we have what we need?
			// Feature request: abstract this to parse any client certificate items, not just kubelet.
			if len(clientKeyPath) > 0 && len(clientCertPath) > 0 {
				// Store the key!
				println("\n[+] Found Kubelet certificate and secret key: " + clientName + "\n")

				var thisClientCertKeyPair ClientCertificateKeyPair
				thisClientCertKeyPair.ClientCertificatePath = clientCertPath
				thisClientCertKeyPair.ClientKeyPath = clientKeyPath
				thisClientCertKeyPair.Name = clientName

				// Parse out the API Server
				thisClientCertKeyPair.APIServer = APIServer
				// Parse out the CA Cert into a string.
				thisClientCertKeyPair.CACert = CACert

				*clientCertificates = append(*clientCertificates, thisClientCertKeyPair)

				break

			}

		}
		file.Close()

	}

	return (nil)
}

// Add the service account tokens for any pods found in /var/lib/kubelet/pods/.
func gatherPodCredentials(serviceAccounts *[]ServiceAccount) {

	// Exit if /var/lib/kubelet/pods does not exist
	const kubeletPodsDir = "/var/lib/kubelet/pods/"
	if _, err := os.Stat(kubeletPodsDir); os.IsNotExist(err) {
		return
	}

	// Store a count of how many service accounts are currently held, so we can report if we found new ones.
	startingNumberServiceAccounts := len(*serviceAccounts)

	// Set a boolean for whether we need to pause to tell the user about new service accounts or non-token secrets.
	// FEATURE REQUEST: create a loot data structure for non-token secrets found on nodes.
	pauseOnExit := false

	// Read the directory for a list of subdirs (pods)
	dirs, err := ioutil.ReadDir(kubeletPodsDir)
	if err != nil {
		return
	}

	const subDir = "/volumes/kubernetes.io~secret/"
	for _, pod := range dirs {
		// In each dir, we are seeking to find its secret volume mounts.
		// Example:
		// ls volumes/kubernetes.io~secret/
		// default-token-5sfvg  registry-htpasswd  registry-pki
		//
		secretPath := kubeletPodsDir + pod.Name() + subDir

		if _, err := os.Stat(secretPath); os.IsNotExist(err) {
			continue
		}
		secrets, err := ioutil.ReadDir(secretPath)
		if err != nil {
			continue
		}
		for _, secret := range secrets {
			secretName := secret.Name()
			if strings.Contains(secretName, "-token-") {
				tokenFilePath := secretPath + secretName + "/token"
				if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
					continue
				}
				tokenBytes, err := ioutil.ReadFile(tokenFilePath)
				if err != nil {
					continue
				}
				token := string(tokenBytes)

				// If possible, name the token for the namespace
				namespacePath := secretPath + "/" + secretName + "/namespace"
				if _, err := os.Stat(namespacePath); os.IsNotExist(err) {
					continue
				}
				namespaceBytes, err := ioutil.ReadFile(namespacePath)
				if err != nil {
					continue
				}
				namespace := string(namespaceBytes)
				fullSecretName := namespace + "/" + secretName
				// FEATURE REQUEST: spell out which node this was found on in the last arg.
				// FEATURE REQUEST: don't add a service account if we already have it.
				*serviceAccounts = append(*serviceAccounts, MakeNewServiceAccount(fullSecretName, string(token), "pod secret harvested from node "))
			} else {
				pauseOnExit = true
				fmt.Printf("[+] Found a secret on the node's filesystem called %s, provided to pod %s, -- explore it with this command:  ls %s\n\n", secretName, pod.Name(), secretPath+secretName)
			}
		}
	}

	newServiceAccountsCount := len(*serviceAccounts) - startingNumberServiceAccounts
	if newServiceAccountsCount > 0 {
		fmt.Printf("\n%d new service accounts pulled from this node's %s directory. Explore them from the sa-menu item on the main menu.\n\nPlease hit Enter to continue.\n", newServiceAccountsCount, kubeletPodsDir)
		pauseOnExit = true
	}
	if pauseOnExit {
		var input string
		fmt.Scanln(&input)
		println(input)
	}

}
