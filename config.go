//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"fmt"
	"io/ioutil"
)

type ServerInfo struct {
	RIPAddress string
	RPort      string
	Token      string // token ASCII text
	CAPath     string // path to ca certificate
	Namespace  string // namespace that this pod's service account is tied to
}

func ParseLocalServerInfo() ServerInfo {

	//creating configInfo type and storing in a variable
	var configInfoVars ServerInfo

	// Reading token file and storing in variable token
	token, errRead := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
	configInfoVars.Token = string(token)

	//Error message If statement based on failure to read the file
	if errRead != nil {
		fmt.Println("Token location error: ", errRead)
	}

	// Reading namespace file and storing in variable namespace
	namespace, errRead := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/namespace")
	if errRead != nil {
		fmt.Println("Namespaces location error", errRead)
	}
	configInfoVars.Namespace = string(namespace)

	//Reading Ca.Crt File and storing in variable caCrt
	configInfoVars.CAPath = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	return configInfoVars
}
