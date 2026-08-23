// Package aws implements Amazon Web Services credential and metadata operations.
package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// DefaultMetadataBaseURL is the default endpoint for the AWS instance metadata service.
const DefaultMetadataBaseURL = "http://169.254.169.254"

// Credentials contains AWS access credentials and their source account name.
type Credentials struct {
	AccountName     string `json:"-"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"Token"`
}

// CredentialsFromEnvironment returns AWS credentials read from environment variables.
func CredentialsFromEnvironment() Credentials {
	return Credentials{
		AccountName:     "AWS Credentials from Environment Variables",
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
}

// MetadataClient retrieves AWS instance metadata and credentials.
type MetadataClient struct {
	BaseURL string
	Client  *http.Client
	Verbose bool
}

// NewMetadataClient returns a metadata client using the default AWS metadata URL and HTTP client.
func NewMetadataClient() MetadataClient {
	return MetadataClient{BaseURL: DefaultMetadataBaseURL, Client: http.DefaultClient}
}

func (c MetadataClient) baseURL() string {
	if c.BaseURL == "" {
		return DefaultMetadataBaseURL
	}
	return c.BaseURL
}

func (c MetadataClient) httpClient() *http.Client {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

// Token retrieves an IMDSv2 session token.
func (c MetadataClient) Token() (string, error) {
	url := c.baseURL() + "/latest/api/token"
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		message := "PUT request to IMDSv2 URL " + url + " failed with HTTP status code " + resp.Status
		fmt.Println(message)
		return "", errors.New(message)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if c.Verbose {
		println("DEBUG: Got IMDSv2 token: " + string(body))
	}
	return string(body), nil
}

// CredentialsV1 retrieves AWS credentials using IMDSv1.
func (c MetadataClient) CredentialsV1() (Credentials, error) {
	var credentials Credentials
	path := c.baseURL() + "/latest/meta-data/iam/security-credentials/"
	resp, err := c.httpClient().Get(path)
	if err != nil {
		return credentials, errors.New("[-] Error - could not perform request http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return credentials, errors.New("AWS IMDS Metadata API responded with " + resp.Status)
	}
	role, err := io.ReadAll(resp.Body)
	if err != nil {
		return credentials, errors.New("error - could not read list of security credentials")
	}
	credentials.AccountName = string(role)
	resp, err = c.httpClient().Get(path + string(role))
	if err != nil {
		return credentials, errors.New("[-] error - could not perform HTTP GET request : " + path + string(role))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return credentials, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return credentials, errors.New("[-] error - could not read security credentials")
	}
	if err := json.Unmarshal(body, &credentials); err != nil {
		return credentials, errors.New("[-] error - problem with JSON unmarshal")
	}
	return credentials, nil
}

// CredentialsV2 retrieves AWS credentials using IMDSv2.
func (c MetadataClient) CredentialsV2() (Credentials, error) {
	var credentials Credentials
	token, err := c.Token()
	if err != nil {
		return credentials, err
	}
	path := c.baseURL() + "/latest/meta-data/iam/security-credentials/"
	role, err := c.getWithToken(path, token)
	if err != nil {
		return credentials, err
	}
	credentials.AccountName = string(role)
	body, err := c.getWithToken(path+string(role), token)
	if err != nil {
		return credentials, err
	}
	if err := json.Unmarshal(body, &credentials); err != nil {
		return credentials, err
	}
	return credentials, nil
}

// RegionAndZone returns the AWS region and availability zone reported by the metadata API.
func (c MetadataClient) RegionAndZone() (string, string, error) {
	path := c.baseURL() + "/latest/meta-data/placement/availability-zone"
	resp, err := c.httpClient().Get(path)
	var body []byte
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, err = io.ReadAll(resp.Body)
		} else {
			err = errors.New(resp.Status)
		}
	}
	if err != nil {
		token, tokenErr := c.Token()
		if tokenErr != nil {
			return "", "", tokenErr
		}
		body, err = c.getWithToken(path, token)
	}
	if err != nil {
		return "", "", err
	}
	zone := strings.TrimSpace(string(body))
	if len(zone) < 2 {
		return "", zone, errors.New("availability zone returned by AWS metadata API is not valid")
	}
	return zone[:len(zone)-1], zone, nil
}

func (c MetadataClient) getWithToken(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}
