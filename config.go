//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"fmt"
	"io/ioutil"
	"os"
)

const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

type ServerInfo struct {
	RIPAddress string
	RPort      string
	Token      string // token ASCII text
	TokenName  string // name of the token
	CAPath     string // path to ca certificate
	Namespace  string // namespace that this pod's service account is tied to
}

func ParseLocalServerInfo() ServerInfo {

	//creating configInfo type and storing in a variable
	var configInfoVars ServerInfo

	// Read IP address and port number for API server out of environment variables
	configInfoVars.RIPAddress = os.Getenv("KUBERNETES_SERVICE_HOST")
	configInfoVars.RPort = os.Getenv("KUBERNETES_SERVICE_PORT")

	// Reading token file and storing in variable token
	const tokenFile = ServiceAccountPath + "token"
	token, errRead := ioutil.ReadFile(tokenFile)
	configInfoVars.Token = string(token)

	//Error message If statement based on failure to read the file
	if errRead != nil {
		fmt.Println("Token location error: ", errRead)
	}

	// Reading namespace file and storing in variable namespace
	namespace, errRead := ioutil.ReadFile(ServiceAccountPath + "namespace")
	if errRead != nil {
		fmt.Println("Namespaces location error", errRead)
	}
	configInfoVars.Namespace = string(namespace)

	// Name the token for its pod
	configInfoVars.TokenName = "Pod ns:" + configInfoVars.Namespace + ":" + os.Getenv("HOSTNAME")

	//Reading Ca.Crt File and storing in variable caCrt
	configInfoVars.CAPath = ServiceAccountPath + "ca.crt"

	return configInfoVars
}
