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

func Builder() ServerInfo {

	//creating config_Info type and storing in a variable
	var config_InfoVars ServerInfo

	// Reading token file and storing in variable token
	token, err_Read := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
	config_InfoVars.Token = string(token)

	//Error message If statement based on failure to read the file
	if err_Read != nil {
		fmt.Println("Token location error: ", err_Read)
	}

	// Reading namespace file and storing in variable namespace
	namespace, err_Read := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err_Read != nil {
		fmt.Println("Namespaces location error", err_Read)
	}
	config_InfoVars.Namespace = string(namespace)

	//Reading Ca.Crt File and storing in variable ca_crt
	config_InfoVars.CAPath = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	return config_InfoVars
}
