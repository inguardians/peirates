// Package gcp implements Google Cloud metadata operations.
package gcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DefaultMetadataBaseURL is the default Google Compute Engine metadata API base URL.
const DefaultMetadataBaseURL = "http://metadata.google.internal/computeMetadata/v1"

// Token represents an OAuth access token returned by the metadata API.
type Token struct {
	Token          string `json:"access_token"`
	Expires        int64  `json:"expires_in"`
	ExpirationTime time.Time
	Type           string `json:"token_type"`
}

// MetadataClient retrieves credentials from the Google Compute Engine metadata API.
type MetadataClient struct {
	BaseURL string
	Client  *http.Client
	Now     func() time.Time
}

// NewMetadataClient returns a metadata client configured with the default endpoint and HTTP client.
func NewMetadataClient() MetadataClient {
	return MetadataClient{BaseURL: DefaultMetadataBaseURL, Client: http.DefaultClient, Now: time.Now}
}

// BearerToken retrieves a bearer token and its expiration time for account.
func (c MetadataClient) BearerToken(account string) (string, time.Time, error) {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = DefaultMetadataBaseURL
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	url := baseURL + "/instance/service-accounts/" + account + "/token"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", now(), err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("GetRequest in GetGCPBearerTokenFromMetadataAPI() failed with error", err)
		return "", now(), err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", now(), err
	}
	raw := string(body)
	if raw == "" || strings.HasPrefix(raw, "ERROR:") || resp.StatusCode != http.StatusOK {
		message := "[-] Error - could not perform request for " + url
		println(message)
		return "", now(), errors.New(message)
	}
	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return "", now(), err
	}
	re := regexp.MustCompile(`^(.*[^.])\.*$`)
	if matches := re.FindSubmatch([]byte(token.Token)); matches != nil {
		token.Token = string(matches[1])
	}
	if token.Type != "Bearer" {
		message := "[-] Error - could not find token in returned body text: " + raw
		println(message)
		return "", now(), errors.New(message)
	}
	requestedAt := now()
	return token.Token, requestedAt.Add(time.Duration(token.Expires)), nil
}
