package peirates

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
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

// ClientCertificateKeyPair stores certificate and key information for one principal.
type ClientCertificateKeyPair struct {
	Name string // Client cert-key pair name
	// ClientKeyPath         string // Client key file path
	// ClientCertificatePath string // Client cert file path
	ClientKeyData         string // Client key data
	ClientCertificateData string // Client cert data
	APIServer             string // URL like https://10.96.0.1:443
	CACert                string // Content of a CA cert
}

// AddNewServiceAccount adds a new service account to the existing slice, but only if the the new one is unique
// Return whether one was added - if it wasn't, it's a duplicate.
func AddNewServiceAccount(name, token, discoveryMethod string, serviceAccountList *[]ServiceAccount) bool {

	// Confirm we don't have this service account already.
	for _, sa := range *serviceAccountList {
		if strings.TrimSpace(sa.Name) == strings.TrimSpace(name) {
			// println("DEBUG: found a service account token we already had: " + sa.Name)
			return false
		}
	}

	*serviceAccountList = append(*serviceAccountList,
		ServiceAccount{
			Name:            name,
			Token:           token,
			DiscoveryTime:   time.Now(),
			DiscoveryMethod: discoveryMethod,
		})

	return true
}

func MakeClientCertificateKeyPair(name, clientCertificateData, clientKeyData, APIServer, CACert string) ClientCertificateKeyPair {
	return ClientCertificateKeyPair{
		Name:                  name,
		ClientKeyData:         clientKeyData,
		ClientCertificateData: clientCertificateData,
		APIServer:             APIServer,
		CACert:                CACert,
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

	// Zero out any client certificate + key, so it's clear what to authenticate with.
	info.ClientCertData = ""
	info.ClientKeyData = ""
	info.ClientCertName = ""

}

func assignAuthenticationCertificateAndKeyToConnection(keypair ClientCertificateKeyPair, info *ServerInfo) {

	// Write out the CACert to a path
	const tmpFileFormat = "*-ca.crt"

	file, err := ioutil.TempFile("", tmpFileFormat)
	if err != nil {
		log.Fatal(err)
	}
	CAPath := file.Name()

	if err != nil {
		println("ERROR: could not open for writing: " + CAPath)
		return
	}
	defer file.Close()

	_, err2 := file.WriteString(keypair.CACert)
	if err2 != nil {
		println("ERROR: could not write certificate authority cert to " + CAPath)
		return
	}

	info.CAPath = CAPath
	info.ClientCertData = keypair.ClientCertificateData
	info.ClientKeyData = keypair.ClientKeyData
	info.ClientCertName = keypair.Name
	info.APIServer = keypair.APIServer
	info.Namespace = "default"

	// Zero out any service account token, so it's clear what to authenticate with.
	info.TokenName = ""
	info.Token = ""

}

func listServiceAccounts(serviceAccounts []ServiceAccount, connectionString ServerInfo) {
	println("\nAvailable Service Accounts:")
	for i, account := range serviceAccounts {
		if account.Name == connectionString.TokenName {
			fmt.Printf("> [%d] %s\n", i, account.Name)
		} else {
			fmt.Printf("  [%d] %s\n", i, account.Name)
		}
	}
}

func switchServiceAccounts(serviceAccounts []ServiceAccount, connectionString *ServerInfo) {

	listServiceAccounts(serviceAccounts, *connectionString)
	println("\nEnter service account number or exit to abort: ")
	var tokNum int
	var input string
	fmt.Scanln(&input)
	if input == "exit" {
		return
	}

	_, err := fmt.Sscan(input, &tokNum)
	if err != nil {
		fmt.Printf("Error parsing service account selection: %s\n", err.Error())
	} else if tokNum < 0 || tokNum >= len(serviceAccounts) {
		fmt.Printf("Service account %d does not exist!\n", tokNum)
	} else {
		assignServiceAccountToConnection(serviceAccounts[tokNum], connectionString)
		fmt.Printf("Selected %s // %s\n", connectionString.TokenName, connectionString.Token)
	}
	return
}

func printJWT(tokenString string) {

	var claims map[string]interface{}

	token, _ := jwt.ParseSigned(tokenString)
	_ = token.UnsafeClaimsWithoutVerification(&claims)

	display.PrintJSON(claims)
}

// parseServiceAccountJWT() takes in a service account JWT and returns its expiration date and name.
func parseServiceAccountJWT(tokenString string) (int64, string) {

	var claims map[string]interface{}

	token, err := jwt.ParseSigned(tokenString)
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		println("Problem with token thingy: %v", err)
	}
	expiration := int64(claims["exp"].(float64))

	// Parse out the name of the service account
	level1 := claims["kubernetes.io"].(map[string]interface{})
	level2 := level1["serviceaccount"].(map[string]interface{})
	name := level2["name"].(string)

	return expiration, name
}
