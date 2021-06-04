package peirates

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
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
	// We will need one more Get to gather this from http://169.254.169.254/latest/meta-data/iam/info
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

	DisplayAWSIAMCredentials(credentials)

	return credentials
}

func EnterIamCredentialsForAWS() (AWSCredentials, error) {

	var credentials AWSCredentials
	var component string

	var input string

	component = "AccessKeyId"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	fmt.Scanln(&input)

	matched, _ := regexp.MatchString(`\w{18,}`, input)
	if !matched {

		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("Invalid Id\n")
	}
	credentials.AccessKeyId = strings.TrimSpace(strings.ToUpper(input))

	component = "SecretAccessKey"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	fmt.Scanln(&input)
	matched, _ = regexp.MatchString(`\w{18,}`, input)
	if !matched {
		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("Invalid Id\n")
	}
	credentials.SecretAccessKey = strings.TrimSpace(input)

	component = "session token"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	fmt.Scanln(&input)
	matched, _ = regexp.MatchString(`\w{5,}`, input)
	if !matched {
		println("String entered isn't a " + component + "\n")
		return credentials, errors.New("Invalid Id\n")
	}
	credentials.SessionToken = strings.TrimSpace(input)

	component = "name or comment"
	println("[+] Enter an AWS " + component + " or hit enter to exit: ")
	fmt.Scanln(&input)
	matched, _ = regexp.MatchString(`\w{1,}`, input)
	if !matched {
		println("Name must include at least one alphanumeric character.\n")
		return credentials, errors.New("Invalid Id\n")
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

	json.Unmarshal(body2, &credentials)

	return credentials, nil

}

func AWSSTSAssumeRole(IAMCredentials AWSCredentials, roleToAssumeArn string) (AssumedCredentials AWSCredentials, err error) {

	matched, _ := regexp.MatchString(`arn:aws:iam::\d{12,}:\w+\/\w+`, roleToAssumeArn)
	if !matched {
		return AssumedCredentials, errors.New("Invalid role entered by user.\n")
	}

	// Get region
	region, _, err := GetAWSRegionAndZone()
	if err != nil {
		println("ERR: Bailing on session because we could not get region.")
		return IAMCredentials, errors.New("Could not get region.")
	}

	// Start a session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(IAMCredentials.AccessKeyId, IAMCredentials.SecretAccessKey, IAMCredentials.SessionToken),
	})

	if err != nil {
		fmt.Println("NewSession Error", err)
		return IAMCredentials, errors.New("Could not start an STS session for assume-role.")
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
		return IAMCredentials, errors.New("Assume role failed.")

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

	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.

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
// This code is an amalgamation of AWS documentation example code.
func ListBucketObjects(IAMCredentials AWSCredentials, bucket string) error {

	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.

	// sess, err := session.NewSession(&aws.Config{
	// 	Region:      aws.String("us-west-2"),
	// 	Credentials: credentials.NewStaticCredentials(IAMCredentials.AccessKeyId, IAMCredentials.SecretAccessKey, IAMCredentials.Token),
	// })

	// if err != nil {
	// 	println("Couldn't create session")
	// 	return
	// }
	// // Deactivate TLS certificate verification, since the pod we run in may not have
	// // a global CA store.
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}

	// // Create S3 service client
	// svc := s3.New(sess, &aws.Config{
	// 	HTTPClient: client,
	// })

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

// exitErrorf is from the AWS documentation
func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
