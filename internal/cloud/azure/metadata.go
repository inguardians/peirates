// Package azure retrieves managed identity tokens from Azure IMDS.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultEndpoint is the Azure IMDS managed identity endpoint.
	DefaultEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
	// DefaultResource is the Azure Resource Manager audience.
	DefaultResource  = "https://management.azure.com/"
	requestTimeout   = 5 * time.Second
	maxResponseBytes = 1 << 20
)

// TokenRequest selects an audience and, optionally, one managed identity.
type TokenRequest struct {
	Resource      string
	ClientID      string
	ObjectID      string
	MSIResourceID string
}

// Validate rejects empty resources and conflicting identity selectors.
func (r TokenRequest) Validate() error {
	if strings.TrimSpace(r.Resource) == "" {
		return errors.New("resource is required")
	}
	selectors := 0
	for _, value := range []string{r.ClientID, r.ObjectID, r.MSIResourceID} {
		if value != "" {
			if strings.TrimSpace(value) == "" {
				return errors.New("identity identifier is empty")
			}
			selectors++
		}
	}
	if selectors > 1 {
		return errors.New("specify only one identity selector")
	}
	return nil
}

// Token contains a validated bearer token and its expiration.
type Token struct {
	AccessToken string
	ExpiresOn   time.Time
	ClientID    string
	Resource    string
}

// HTTPError retains structured Azure error details without the raw response body.
type HTTPError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Azure IMDS HTTP %d: %s %s", e.StatusCode, e.Code, e.Description)
}

// MetadataClient supports injectable HTTP transport, endpoint, and clock for fixtures.
type MetadataClient struct {
	HTTPClient *http.Client
	Endpoint   string
	Now        func() time.Time
}

// NewMetadataClient uses a dedicated direct transport, without environment proxies.
func NewMetadataClient() *MetadataClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	// Closing each connection also prevents net/http replay of a GET on a stale connection.
	transport.DisableKeepAlives = true
	return &MetadataClient{
		HTTPClient: &http.Client{Transport: transport, Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Endpoint: DefaultEndpoint,
		Now:      time.Now,
	}
}

// RequestToken makes one bounded request. It does not retry or refresh tokens.
func (c *MetadataClient) RequestToken(ctx context.Context, selection TokenRequest) (Token, error) {
	if err := selection.Validate(); err != nil {
		return Token{}, err
	}
	endpoint, err := url.Parse(c.Endpoint)
	if err != nil {
		return Token{}, fmt.Errorf("Azure IMDS endpoint: %w", err)
	}
	query := endpoint.Query()
	query.Set("api-version", "2018-02-01")
	query.Set("resource", selection.Resource)
	for name, value := range map[string]string{"client_id": selection.ClientID, "object_id": selection.ObjectID, "msi_res_id": selection.MSIResourceID} {
		query.Del(name)
		if value != "" {
			query.Set(name, value)
		}
	}
	endpoint.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Metadata", "true")
	// Enforce the redirect policy even with an injected fixture client.
	client := *c.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("Azure IMDS request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return Token{}, fmt.Errorf("read Azure IMDS response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return Token{}, errors.New("Azure IMDS response exceeds 1 MiB")
	}
	if response.StatusCode != http.StatusOK {
		var detail struct {
			Code        string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &detail)
		return Token{}, &HTTPError{StatusCode: response.StatusCode, Code: detail.Code, Description: detail.Description}
	}
	var wire struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresOn   json.RawMessage `json:"expires_on"`
		ClientID    string          `json:"client_id"`
		Resource    string          `json:"resource"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return Token{}, errors.New("malformed Azure IMDS token response")
	}
	if strings.TrimSpace(wire.AccessToken) == "" || !strings.EqualFold(wire.TokenType, "Bearer") {
		return Token{}, errors.New("Azure IMDS response requires a nonempty bearer token")
	}
	if wire.Resource != "" && wire.Resource != selection.Resource {
		return Token{}, errors.New("Azure IMDS returned a token for a different resource")
	}
	expiry := string(wire.ExpiresOn)
	if strings.HasPrefix(expiry, `"`) {
		if err := json.Unmarshal(wire.ExpiresOn, &expiry); err != nil {
			return Token{}, errors.New("invalid Azure IMDS expires_on")
		}
	}
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return Token{}, errors.New("invalid Azure IMDS expires_on")
	}
	expiresOn := time.Unix(seconds, 0).UTC()
	if !expiresOn.After(c.Now()) {
		return Token{}, errors.New("Azure IMDS returned an expired token")
	}
	return Token{AccessToken: wire.AccessToken, ExpiresOn: expiresOn, ClientID: wire.ClientID, Resource: selection.Resource}, nil
}
