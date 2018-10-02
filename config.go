//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

// Locations of the svc account and token for i/o reads
// account token -  /run/secrets/kubernetes.io/serviceaccount
// name space
package main

import (
	//	"os/exec"
	"fmt"
	"io/ioutil"
)

// WAS
// type Config_Info struct {
//	token       []byte
//	ca_crt_path []byte
//	namespaces  []byte
//	my_config   string
//	}

type serverInfo struct {
	rIPAddress string
	rPort      string
	token      string // token ASCII text
	caPath     string // path to ca certificate
	namespace  string // namespace that this pod's service account is tied to
}

func Builder() {

	//creating config_Info type and storing in a variable
	var config_InfoVars = config_Info{}

	// Reading token file and storing in variable token
	config_InfoVars.token, config_InfoVars.err_Read = ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")

	//Error message If statement based on failure to read the file
	if config_InfoVars.err_Read != nil {
		fmt.Println("Token location error: ", config_InfoVars.err_Read)
	}

	// Reading namespaces file and storing in variable namespaces
	namespaces, err_Read := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err_Read != nil {
		fmt.Println("Namespaces location error", err_Read)
	}
	config_InfoVars.namespaces = string(namespaces)

	//Reading Ca.Crt File and storing in variable ca_crt
	config_InfoVars.ca_crt, config_InfoVars.err_Read = ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if config_InfoVars.err_Read != nil {
		fmt.Println("Ca.Crt location error: ", config_InfoVars.err_Read)
	}

}

// Main Fucntion of the program

func main() {
	Builder()
}
