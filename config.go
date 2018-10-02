//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps
import (
	"fmt"
	"io/ioutil"
)

type ServerInfo struct {
	rIPAddress string
	rPort      string
	token      string // token ASCII text
	caPath     string // path to ca certificate
	namespace  string // namespace that this pod's service account is tied to
}

func Builder() ServerInfo {

	//creating config_Info type and storing in a variable
	var config_InfoVars ServerInfo

	// Reading token file and storing in variable token
	token, err_Read := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
    config_InfoVars.token = string(token)

	//Error message If statement based on failure to read the file
	if err_Read != nil {
		fmt.Println("Token location error: ", err_Read)
	}

	// Reading namespace file and storing in variable namespace
	namespace, err_Read := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err_Read != nil {
		fmt.Println("Namespaces location error", err_Read)
	}
	config_InfoVars.namespace = string(namespace)

	//Reading Ca.Crt File and storing in variable ca_crt
	config_InfoVars.caPath = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	return config_InfoVars
}

