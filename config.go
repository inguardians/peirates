//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"fmt"
	"io/ioutil"
	"os"
)

const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

type ServerInfo struct {
	RIPAddress         string
	RPort              string
	CAPath             string // location of the certificate authority's cert file
	Token              string // service account token ASCII text, if present
	TokenName          string // name of the service account token, if present
	KubeconfigFileName string // name for the kubeconfig file, if present
	KubeconfigFilePath string // path to the kubeconfig file, if present
	Namespace          string // namespace that this pod's service account is tied to
	UseAuthCanI        bool
}

func ParseLocalServerInfo() ServerInfo {

	// Creating an object of ServerInfo type, which we'll poppulate in this function.
	var configInfoVars ServerInfo

	// Check to see if the configuration information we require is in environment variables and
	// a token file, as it would be in a running pod under default configuration.

	// Read IP address and port number for API server out of environment variables
	configInfoVars.RIPAddress = os.Getenv("KUBERNETES_SERVICE_HOST")
	configInfoVars.RPort = os.Getenv("KUBERNETES_SERVICE_PORT")

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

func checkForNodeCredentials(KubeconfigFiles *[]KubeconfigFile) error {

	// Paths to explore:
	// /etc/kubernetes/kubelet.conf
	// /var/lib/kubelet/kubeconfig
	// /

	// Determine if one of the paths above exists and use it to get the kubelet's kubeconfig file
	kubeletKubeconfigFilePaths := make([]string, 0)

	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/etc/kubernetes/kubelet.conf")
	kubeletKubeconfigFilePaths = append(kubeletKubeconfigFilePaths, "/var/lib/kubelet/kubeconfig")

	for _, path := range kubeletKubeconfigFilePaths {
		// On each path, check for existence of the file.
		if _, err := os.Stat(path); os.IsNotExist(err) {
			//println("DEBUG: no file found at " + path)
			continue
		}

		var thisKubeconfigFile KubeconfigFile
		thisKubeconfigFile.Name = path
		thisKubeconfigFile.Path = path

		*KubeconfigFiles = append(*KubeconfigFiles, thisKubeconfigFile)
	}

	return (nil)
}
