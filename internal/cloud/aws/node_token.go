package aws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
)

const (
	nodeRequestTimeout   = 5 * time.Second
	nodeDiscoveryTimeout = 45 * time.Second
	nodeResponseLimit    = 1 << 20
	maxClusterCandidates = 8
)

var (
	clusterNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
	regionPattern      = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]+$`)
	instanceIDPattern  = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
	accountIDPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	roleNamePattern    = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	hostnamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// NodeTokenOptions selects optional overrides and the independently trusted API target.
type NodeTokenOptions struct {
	ClusterName string
	Region      string
	AllowIMDSv1 bool
	TrustedCA   []byte
	APIEndpoint string
}

// NodeTokenResult contains a bearer credential and nonsecret acquisition provenance.
// Token must only be displayed as an explicitly requested command result.
type NodeTokenResult struct {
	Token          string
	ClusterName    string
	Region         string
	RegionSource   string
	ClusterSource  string
	InstanceID     string
	AccountID      string
	RoleName       string
	RoleIdentity   string
	PrivateDNSName string
	AcquiredAt     time.Time
	ExpiresAt      time.Time
	Corroborated   bool
	Diagnostics    []string
}

// InstanceDescription is the bounded result of looking up exactly one EC2 instance.
type InstanceDescription struct {
	InstanceID     string
	PrivateDNSName string
	Tags           map[string]string
}

// ClusterDescription contains the trust information returned by EKS DescribeCluster.
type ClusterDescription struct {
	Name     string
	Endpoint string
	CA       []byte
}

// NodeDiscovery performs only instance-scoped EC2 lookup and named EKS lookup.
// Credentials are always supplied explicitly from this acquisition's IMDS response.
type NodeDiscovery interface {
	DescribeInstance(context.Context, string, string, Credentials) (InstanceDescription, error)
	DescribeCluster(context.Context, string, string, Credentials) (ClusterDescription, error)
}

// NodeTokenClient acquires credentials without consulting ambient SDK credential sources.
// The exported dependencies allow deterministic protocol tests without CLI endpoint overrides.
type NodeTokenClient struct {
	MetadataBaseURL string
	HTTPClient      *http.Client
	Discovery       NodeDiscovery
	Now             func() time.Time
}

// NewNodeTokenClient returns an isolated, proxy-free, redirect-rejecting client.
func NewNodeTokenClient() *NodeTokenClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &NodeTokenClient{MetadataBaseURL: DefaultMetadataBaseURL, HTTPClient: &http.Client{
		Transport: transport, Timeout: nodeRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, Now: time.Now}
}

// GenerateNodeToken discovers the local EC2 node and signs an EKS authentication token.
func GenerateNodeToken(ctx context.Context, options NodeTokenOptions) (NodeTokenResult, error) {
	return NewNodeTokenClient().Generate(ctx, options)
}

// Generate obtains fresh node credentials, resolves cluster identity, and signs locally.
func (c *NodeTokenClient) Generate(ctx context.Context, options NodeTokenOptions) (NodeTokenResult, error) {
	var result NodeTokenResult
	if options.ClusterName != "" && !clusterNamePattern.MatchString(options.ClusterName) {
		return result, errors.New("invalid cluster-name override")
	}
	if options.Region != "" && !regionPattern.MatchString(options.Region) {
		return result, errors.New("invalid region override")
	}
	ctx, cancel := context.WithTimeout(ctx, nodeDiscoveryTimeout)
	defer cancel()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	httpClient := c.boundedClient()
	base := c.MetadataBaseURL
	if base == "" {
		base = DefaultMetadataBaseURL
	}
	metadata := nodeMetadata{base: strings.TrimRight(base, "/"), client: httpClient}
	body, status, err := metadata.request(ctx, http.MethodPut, "/latest/api/token")
	if err != nil {
		return result, fmt.Errorf("IMDSv2 token request: %w", err)
	}
	if status == http.StatusOK {
		metadata.token = strings.TrimSpace(string(body))
		if metadata.token == "" || len(metadata.token) > 4096 || strings.ContainsAny(metadata.token, "\r\n") {
			return result, errors.New("IMDSv2 returned an invalid session token")
		}
	} else if options.AllowIMDSv1 && (status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusMethodNotAllowed) {
		result.Diagnostics = append(result.Diagnostics, "IMDSv2 unavailable; explicitly enabled IMDSv1 compatibility used")
	} else {
		return result, fmt.Errorf("IMDSv2 token request returned HTTP %d (IMDSv1 fallback requires --allow-imdsv1 and HTTP 403, 404, or 405)", status)
	}
	roleBody, err := metadata.get(ctx, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return result, fmt.Errorf("instance-role lookup: %w", err)
	}
	role := strings.TrimSpace(string(roleBody))
	if !roleNamePattern.MatchString(role) {
		return result, errors.New("IMDS returned an invalid or ambiguous instance-role name")
	}
	credentialBody, err := metadata.get(ctx, "/latest/meta-data/iam/security-credentials/"+url.PathEscape(role))
	if err != nil {
		return result, fmt.Errorf("instance-role credentials: %w", err)
	}
	var document struct {
		Credentials
		Code       string
		Expiration time.Time
	}
	if json.Unmarshal(credentialBody, &document) != nil || document.Code != "Success" ||
		!validCredentialField(document.AccessKeyID) || !validCredentialField(document.SecretAccessKey) || !validCredentialField(document.SessionToken) {
		return result, errors.New("IMDS returned incomplete or invalid instance-role credentials")
	}
	if !document.Expiration.After(now()) {
		return result, errors.New("IMDS instance-role credentials are expired")
	}
	document.AccountName = role
	identityBody, err := metadata.get(ctx, "/latest/dynamic/instance-identity/document")
	if err != nil {
		return result, fmt.Errorf("instance identity: %w", err)
	}
	var identity struct{ Region, InstanceID, AccountID string }
	if json.Unmarshal(identityBody, &identity) != nil || !regionPattern.MatchString(identity.Region) ||
		!instanceIDPattern.MatchString(identity.InstanceID) || !accountIDPattern.MatchString(identity.AccountID) {
		return result, errors.New("IMDS returned an invalid instance identity document")
	}
	result.Region, result.RegionSource = identity.Region, "IMDS instance identity document"
	if options.Region != "" {
		result.Region, result.RegionSource = options.Region, "--region override"
	}
	result.InstanceID, result.AccountID, result.RoleName = identity.InstanceID, identity.AccountID, role
	result.RoleIdentity = identity.AccountID + "/" + role
	discovery := c.Discovery
	if discovery == nil {
		discovery = &nodeAWSAPI{client: httpClient, now: now}
	}
	candidates := map[string]string{}
	if options.ClusterName != "" {
		candidates[options.ClusterName] = "--cluster-name override"
	} else {
		fallbackReason := "EC2 instance tags contain no usable cluster name"
		instance, lookupErr := discovery.DescribeInstance(ctx, result.Region, result.InstanceID, document.Credentials)
		if lookupErr != nil {
			fallbackReason = nodeDiscoveryFailureReason(lookupErr)
		} else if instance.InstanceID != result.InstanceID {
			return result, errors.New("EC2 response did not identify the requested instance")
		} else {
			if hostnamePattern.MatchString(instance.PrivateDNSName) {
				result.PrivateDNSName = instance.PrivateDNSName
			}
			for key, value := range instance.Tags {
				name := ""
				if key == "aws:eks:cluster-name" {
					name = value
				}
				if strings.HasPrefix(key, "kubernetes.io/cluster/") && value == "owned" {
					name = strings.TrimPrefix(key, "kubernetes.io/cluster/")
				}
				if clusterNamePattern.MatchString(name) {
					candidates[name] = "EC2 instance tags"
				}
			}
		}
		if len(candidates) == 0 {
			result.Diagnostics = append(result.Diagnostics, fallbackReason+"; trying IMDS bootstrap data")
			userData, dataErr := metadata.get(ctx, "/latest/user-data")
			if dataErr != nil {
				return result, fmt.Errorf("cluster discovery failed: %s; IMDS bootstrap data unavailable (%s); use --cluster-name", fallbackReason, dataErr)
			}
			candidates, err = bootstrapClusterCandidates(userData)
			if err != nil {
				return result, err
			}
			if len(candidates) == 0 {
				return result, errors.New("cluster discovery failed: no recognized literal cluster name in instance tags or bootstrap data; use --cluster-name")
			}
		}
	}
	if len(candidates) > maxClusterCandidates {
		return result, errors.New("cluster discovery returned more than eight candidates")
	}
	if result.PrivateDNSName == "" {
		if hostname, hostnameErr := metadata.get(ctx, "/latest/meta-data/local-hostname"); hostnameErr == nil {
			value := strings.TrimSpace(string(hostname))
			if hostnamePattern.MatchString(value) {
				result.PrivateDNSName = value
			}
		}
	}
	name, corroborated, err := resolveNodeCluster(ctx, discovery, candidates, result.Region, document.Credentials, options)
	if err != nil {
		return result, err
	}
	result.ClusterName, result.ClusterSource, result.Corroborated = name, candidates[name], corroborated
	if !corroborated {
		result.Diagnostics = append(result.Diagnostics, "Cluster name is a discovery candidate; API trust has not been corroborated through EKS")
	}
	if err := ctx.Err(); err != nil {
		return result, errors.New("node token discovery deadline exceeded")
	}
	result.AcquiredAt = now().UTC()
	result.Token, result.ExpiresAt, err = signNodeToken(result.ClusterName, result.Region, document.Credentials, document.Expiration, result.AcquiredAt)
	return result, err
}

func validCredentialField(value string) bool {
	return value != "" && len(value) <= 16384 && !strings.ContainsAny(value, " \t\r\n")
}

func (c *NodeTokenClient) boundedClient() *http.Client {
	if c.HTTPClient == nil {
		return NewNodeTokenClient().HTTPClient
	}
	clone := *c.HTTPClient
	clone.Timeout = nodeRequestTimeout
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

type nodeMetadata struct {
	base, token string
	client      *http.Client
}

func (m nodeMetadata) request(ctx context.Context, method, path string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, nodeRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, nil)
	if err != nil {
		return nil, 0, errors.New("invalid metadata request")
	}
	if method == http.MethodPut {
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	}
	if m.token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", m.token)
	}
	response, err := m.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("metadata request failed or timed out")
	}
	defer response.Body.Close()
	body, err := readNodeResponse(response.Body)
	return body, response.StatusCode, err
}

func (m nodeMetadata) get(ctx context.Context, path string) ([]byte, error) {
	body, status, err := m.request(ctx, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("metadata returned HTTP %d", status)
	}
	return body, nil
}

func readNodeResponse(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, nodeResponseLimit+1))
	if err != nil {
		return nil, errors.New("could not read bounded response")
	}
	if len(body) > nodeResponseLimit {
		return nil, errors.New("response exceeds 1 MiB limit")
	}
	return body, nil
}

func regionalEndpoint(service, region string) (string, error) {
	endpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, func(options *endpoints.Options) {
		options.STSRegionalEndpoint = endpoints.RegionalSTSEndpoint
	})
	if err != nil {
		return "", errors.New("unsupported AWS service region")
	}
	return endpoint.URL, nil
}

func signNodeToken(cluster, region string, creds Credentials, credentialExpiry, now time.Time) (string, time.Time, error) {
	if !clusterNamePattern.MatchString(cluster) || !regionPattern.MatchString(region) {
		return "", time.Time{}, errors.New("invalid signing cluster or region")
	}
	if !credentialExpiry.After(now) {
		return "", time.Time{}, errors.New("instance-role credentials expired during discovery")
	}
	endpoint, err := regionalEndpoint("sts", region)
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint+"/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	if err != nil {
		return "", time.Time{}, errors.New("could not construct STS signing request")
	}
	req.Header.Set("x-k8s-aws-id", cluster)
	signer := v4.NewSigner(credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken))
	if _, err := signer.Presign(req, nil, "sts", region, 60*time.Second, now); err != nil {
		return "", time.Time{}, errors.New("could not sign EKS token")
	}
	// AWS CLI refreshes at 14 minutes although authenticator accepts signatures for 15.
	expires := now.Add(14 * time.Minute)
	if credentialExpiry.Before(expires) {
		expires = credentialExpiry
	}
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(req.URL.String())), expires, nil
}

func resolveNodeCluster(ctx context.Context, discovery NodeDiscovery, candidates map[string]string, region string, creds Credentials, options NodeTokenOptions) (string, bool, error) {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 1 && len(options.TrustedCA) == 0 {
		return names[0], false, nil
	}
	var matches []string
	for _, name := range names {
		description, err := discovery.DescribeCluster(ctx, region, name, creds)
		if err != nil {
			continue
		}
		if description.Name != name {
			return "", false, errors.New("EKS response did not identify the requested cluster")
		}
		if len(options.TrustedCA) == 0 {
			continue
		}
		matchesCA, err := matchingNodeCA(options.TrustedCA, description.CA)
		if err != nil {
			return "", false, err
		}
		matchesHost := true
		if target := comparableAPIHostname(options.APIEndpoint); target != "" {
			endpoint, parseErr := url.Parse(description.Endpoint)
			matchesHost = parseErr == nil && endpoint.Scheme == "https" && strings.EqualFold(target, endpoint.Hostname())
		}
		if matchesCA && matchesHost {
			matches = append(matches, name)
		} else if len(names) == 1 {
			return "", false, errors.New("discovered EKS cluster does not match the trusted API CA or target hostname")
		}
	}
	if len(matches) == 1 {
		return matches[0], true, nil
	}
	if len(names) == 1 {
		return names[0], false, nil
	}
	labels := make([]string, 0, len(names))
	for _, name := range names {
		labels = append(labels, name+" ("+candidates[name]+")")
	}
	return "", false, fmt.Errorf("ambiguous cluster candidates: %s; unable to uniquely match trusted API CA; use --cluster-name", strings.Join(labels, ", "))
}

func comparableAPIHostname(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || host == "kubernetes" || host == "kubernetes.default" || strings.HasSuffix(host, ".svc") || strings.Contains(host, ".svc.") {
		return ""
	}
	return host
}

func matchingNodeCA(trusted, candidate []byte) (bool, error) {
	parse := func(data []byte) ([][]byte, error) {
		var certificates [][]byte
		for len(strings.TrimSpace(string(data))) > 0 {
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("invalid cluster CA certificate data")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("invalid cluster CA certificate data")
			}
			certificates = append(certificates, certificate.Raw)
			data = rest
		}
		if len(certificates) == 0 {
			return nil, errors.New("missing cluster CA certificate data")
		}
		return certificates, nil
	}
	a, err := parse(trusted)
	if err != nil {
		return false, err
	}
	b, err := parse(candidate)
	if err != nil {
		return false, err
	}
	for _, x := range a {
		for _, y := range b {
			if string(x) == string(y) {
				return true, nil
			}
		}
	}
	return false, nil
}
