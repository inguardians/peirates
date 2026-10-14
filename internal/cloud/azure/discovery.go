package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	// DefaultConfigPath is the Azure cloud configuration written on AKS nodes.
	DefaultConfigPath = "/etc/kubernetes/azure.json"
	// DefaultInstanceEndpoint supplies VM metadata, including AKS instance tags.
	DefaultInstanceEndpoint = "http://169.254.169.254/metadata/instance"
	// KubeletIdentityTag may contain the AKS kubelet managed identity client ID.
	KubeletIdentityTag = "aks-managed-kubeletIdentityClientID"
)

var clientIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IdentityCandidate is a client ID found in configuration, not a proven IMDS assignment.
type IdentityCandidate struct {
	ClientID string
	Sources  []string
}

// IdentityDiscovery preserves successful findings when another source fails.
type IdentityDiscovery struct {
	Candidates []IdentityCandidate
	Warnings   []error
}

// DiscoverIdentities reads only the Azure config identity fields and the AKS
// kubelet identity tag. It neither requests tokens nor enumerates ARM resources.
func (c *MetadataClient) DiscoverIdentities(ctx context.Context, configPath string) IdentityDiscovery {
	var result IdentityDiscovery
	byID := make(map[string][]string)
	add := func(id, source string) {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			return
		}
		if !clientIDPattern.MatchString(id) {
			result.Warnings = append(result.Warnings, fmt.Errorf("%s: invalid managed identity client ID (expected a GUID)", source))
			return
		}
		for _, previous := range byID[id] {
			if previous == source {
				return
			}
		}
		byID[id] = append(byID[id], source)
	}
	configID, err := configClientID(configPath)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Errorf("%s: %w", configPath, err))
	} else {
		add(configID, configPath+" (userAssignedIdentityID)")
	}
	tagIDs, err := c.instanceClientIDs(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Errorf("IMDS instance tags: %w", err))
	} else {
		for _, id := range tagIDs {
			add(id, "IMDS tag "+KubeletIdentityTag)
		}
	}
	for id, sources := range byID {
		result.Candidates = append(result.Candidates, IdentityCandidate{ClientID: id, Sources: sources})
	}
	sort.Slice(result.Candidates, func(i, j int) bool { return result.Candidates[i].ClientID < result.Candidates[j].ClientID })
	return result
}

func configClientID(path string) (string, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil // Expected when running in a pod or on a non-AKS host.
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("Azure config must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxResponseBytes+1))
	if err != nil {
		return "", errors.New("could not read Azure config")
	}
	if len(body) > maxResponseBytes {
		return "", errors.New("Azure config exceeds 1 MiB")
	}
	var config struct {
		UseManagedIdentity bool   `json:"useManagedIdentityExtension"`
		ClientID           string `json:"userAssignedIdentityID"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		// JSON error text can include unrelated credential fields or their values.
		return "", errors.New("malformed Azure config identity fields")
	}
	if !config.UseManagedIdentity {
		return "", nil
	}
	return config.ClientID, nil
}

func (c *MetadataClient) instanceClientIDs(ctx context.Context) ([]string, error) {
	endpoint, err := url.Parse(c.InstanceEndpoint)
	if err != nil {
		return nil, errors.New("invalid instance metadata endpoint")
	}
	endpoint.RawQuery = url.Values{"api-version": {"2021-02-01"}}.Encode()
	body, err := c.getMetadata(ctx, endpoint)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			// Discovery does not need arbitrary error descriptions from metadata.
			return nil, fmt.Errorf("HTTP %d", httpErr.StatusCode)
		}
		return nil, err
	}
	var instance struct {
		Compute struct {
			Tags []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"tagsList"`
		} `json:"compute"`
	}
	if err := json.Unmarshal(body, &instance); err != nil {
		return nil, errors.New("malformed instance metadata tags")
	}
	var ids []string
	for _, tag := range instance.Compute.Tags {
		if tag.Name == KubeletIdentityTag {
			ids = append(ids, tag.Value)
		}
	}
	return ids, nil
}
