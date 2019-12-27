package peirates

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// AWSCredentials stores the credentialsa
type AWSCredentials struct {
	accountName string
	// We will need one more Get to gather this from http://169.254.169.254/latest/meta-data/iam/info
	// InstanceProfileArn  string
	// If we parse this, we can freshen this only as necessary
	// Expiration			string `json:"Expiration"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// PullIamCredentialsFromAWS requests access credentials from the AWS metadata API
func PullIamCredentialsFromAWS() AWSCredentials {

	var credentials AWSCredentials

	response, err := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		println("[-] Error - could not perform request http://169.254.169.254/latest/meta-data/iam/security-credentials/ ")
	}
	// Parse result as an account, then construct a request asking for that account's credentials
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	account := string(body)
	credentials.accountName = account
	// println(account)

	request := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + account
	response2, err := http.Get(request)
	if err != nil {
		println("[-] Error - could not perform request ", request)
	}
	defer response2.Body.Close()
	body2, err := ioutil.ReadAll(response2.Body)

	json.Unmarshal(body2, &credentials)

	return credentials

}

// DisplayAWSIAMCredentials prints the IAM credentials gathered out to stdout.
func DisplayAWSIAMCredentials(IAMCredentials AWSCredentials) {
	println("IAM Credentials for user " + IAMCredentials.accountName + " are: \n")
	println("aws_access_key_id = " + IAMCredentials.AccessKeyId)
	println("aws_secret_access_key = " + IAMCredentials.SecretAccessKey)
	println("aws_session_token = " + IAMCredentials.Token)
}

// StartS3Session creates a session with S3 using AWS Credentials.
func StartS3Session(IAMCredentials AWSCredentials) *s3.S3 {

	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(IAMCredentials.AccessKeyId, IAMCredentials.SecretAccessKey, IAMCredentials.Token),
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
		fmt.Println("Last modified:", *item.LastModified)
		fmt.Println("Size:         ", *item.Size)
		fmt.Println("Storage class:", *item.StorageClass)
		fmt.Println("")
	}
	return nil
}

// ListBuckets lists the buckets accessible from this IAM account.
func ListBuckets(IAMCredentials AWSCredentials) error {
	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.
	svc := StartS3Session(IAMCredentials)

	result, err := svc.ListBuckets(nil)
	if err != nil {
		nonexitErrorf("Unable to list buckets, %v", err)

		return err
	}

	fmt.Println("Buckets:")

	for _, b := range result.Buckets {
		fmt.Printf("* %s created on %s\n",
			aws.StringValue(b.Name), aws.TimeValue(b.CreationDate))
	}
	return nil
}

func nonexitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
}

// exitErrorf is from the AWS documentation
func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
