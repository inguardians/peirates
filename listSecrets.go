package peirates

func listSecrets(connectionString *ServerInfo) {

	secrets, serviceAccountTokens := getSecretList(*connectionString)
	for _, secret := range secrets {
		println("[+] Secret found: ", secret)
	}
	for _, svcAcct := range serviceAccountTokens {
		println("[+] Service account found: ", svcAcct)
	}

}
