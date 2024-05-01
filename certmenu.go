package peirates

import (
	"fmt"
	"strings"
)

func certMenu(clientCertificates *[]ClientCertificateKeyPair, connectionString *ServerInfo, interactive bool) {
	println("Current certificate-based authentication: ", connectionString.ClientCertName)
	println("\n")
	println("[1] List client certificates [list]")
	println("[2] Switch active client certificates [switch]")
	// println("[3] Enter new client certificate and key [add]")
	// println("[4] Export service accounts to JSON [export]")
	// println("[5] Import service accounts from JSON [import]")
	// println("[6] Decode a stored or entered service account token (JWT) [decode]")

	println("\n")

	var input string

	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Printf("Error reading input: %s\n", err.Error())
		pauseToHitEnter(interactive)
		return
	}
	switch strings.ToLower(input) {
	case "1", "list":
		println("\nAvailable Client Certificate/Key Pairs:")
		for i, account := range *clientCertificates {
			fmt.Printf("  [%d] %s\n", i, account.Name)
		}
	case "2", "switch":
		println("\nAvailable Client Certificate/Key Pairs:")
		for i, account := range *clientCertificates {
			fmt.Printf("  [%d] %s\n", i, account.Name)
		}
		println("\nEnter certificate/key pair number or exit to abort: ")
		var tokNum int
		_, err = fmt.Scanln(&input)
		if err != nil {
			fmt.Printf("Error reading input: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		}
		if input == "exit" {
			pauseToHitEnter(interactive)
			return
		}

		_, err := fmt.Sscan(input, &tokNum)
		if err != nil {
			fmt.Printf("Error parsing certificate/key pair selection: %s\n", err.Error())
		} else if tokNum < 0 || tokNum >= len(*clientCertificates) {
			fmt.Printf("Certificate/key pair  %d does not exist!\n", tokNum)
		} else {
			assignAuthenticationCertificateAndKeyToConnection((*clientCertificates)[tokNum], connectionString)
			fmt.Printf("Selected %s\n", connectionString.ClientCertName)
		}
	}
}
