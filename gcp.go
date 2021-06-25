package peirates

import "strings"

// GetGCPBearerTokenFromMetadataAPI takes the name of a GCP service account and returns a token
func GetGCPBearerTokenFromMetadataAPI(account string) string {

	headers := []HeaderLine{
		HeaderLine{"Metadata-Flavor", "Google"},
	}
	urlSvcAccount := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" + account + "/token"

	reqTokenRaw := GetRequest(urlSvcAccount, headers, false)
	if (reqTokenRaw == "") || (strings.HasPrefix(reqTokenRaw, "ERROR:")) {
		println("[-] Error - could not perform request ", urlSvcAccount)
		return ("ERROR")
	}
	// Body will look like this, unless error has occurred: {"access_token":"xxxxxxx","expires_in":2511,"token_type":"Bearer"}
	// TODO: Add a check for a 200 status code
	// Split the body on "" 's for now
	// TODO: Parse this as JSON
	tokenElements := strings.Split(string(reqTokenRaw), "\"")
	if tokenElements[1] == "access_token" {
		return (tokenElements[3])
	} else {
		println("[-] Error - could not find token in returned body text: ", string(reqTokenRaw))
		return "ERROR"
	}
}
