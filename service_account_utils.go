package peirates

import (
	"time"

	"github.com/trung/jwt-tools/display"
	"gopkg.in/square/go-jose.v2/jwt"
)

// SERVICE ACCOUNT MANAGEMENT functions

// ServiceAccount stores service account information.
type ServiceAccount struct {
	Name            string    // Service account name
	Token           string    // Service account token
	DiscoveryTime   time.Time // Time the service account was discovered
	DiscoveryMethod string    // How the service account was discovered (file on disk, secrets, user input, etc.)
}

// KubeconfigFile stores the path to a kubeconfig file, like a Kubelet, kube-proxy, or a user.
type KubeconfigFile struct {
	Name string
	Path string // Path to the kubeconfig file

}

// MakeNewServiceAccount creates a new service account with the provided name,
// token, and discovery method, while setting the DiscoveryTime to time.Now()
func MakeNewServiceAccount(name, token, discoveryMethod string) ServiceAccount {
	return ServiceAccount{
		Name:            name,
		Token:           token,
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: discoveryMethod,
	}
}

func MakeNewKubeconfigFile(name, path string) KubeconfigFile {
	return KubeconfigFile{
		Name: name,
		Path: path,
	}
}

func acceptServiceAccountFromUser() ServiceAccount {
	println("\nPlease paste in a new service account token or hit ENTER to maintain current token.")
	serviceAccount := ServiceAccount{
		Name:            "",
		Token:           "",
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: "User Input",
	}
	println("\nWhat do you want to name this service account?")
	serviceAccount.Name, _ = ReadLineStripWhitespace()
	println("\nPaste the service account token and hit ENTER:")
	serviceAccount.Token, _ = ReadLineStripWhitespace()

	return serviceAccount
}

func assignServiceAccountToConnection(account ServiceAccount, info *ServerInfo) {
	info.TokenName = account.Name
	info.Token = account.Token

	// Zero out any kubeconfig file, so it's clear what to authenticate with.
	info.KubeconfigFileName = ""
	info.KubeconfigFilePath = ""

}

func assignKubeconfigFileToConnection(thisKubeconfigFile KubeconfigFile, info *ServerInfo) {
	info.KubeconfigFileName = thisKubeconfigFile.Name
	info.KubeconfigFilePath = thisKubeconfigFile.Path

	// Zero out any service account token, so it's clear what to authenticate with.
	info.TokenName = ""
	info.Token = ""

}

func printJWT(tokenString string) {

	var claims map[string]interface{}

	token, _ := jwt.ParseSigned(tokenString)
	_ = token.UnsafeClaimsWithoutVerification(&claims)

	display.PrintJSON(claims)
}
