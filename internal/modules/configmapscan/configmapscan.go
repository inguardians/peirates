// Package configmapscan locates credential-shaped values in readable ConfigMaps.
package configmapscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

const (
	pageSize         = 10
	maxPages         = 200
	maxObjects       = 2000
	maxResponseBytes = 16 << 20
	maxFindings      = 5000
	requestTimeout   = 10 * time.Second
)

type requester func(context.Context, model.ServerInfo, string, string) (corev1.ConfigMapList, error)

type identity struct {
	label string
	cfg   model.ServerInfo
}

type finding struct {
	location   string
	server     string
	kind       string
	confidence string
	identities map[string]bool
}

// Run scans each distinct active or stored credential without changing the active session.
// Its output contains locations and detector names, never ConfigMap values.
func Run(ctx context.Context, base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair, out io.Writer) error {
	return run(ctx, base, accounts, certs, out, listPage)
}

func run(ctx context.Context, base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair, out io.Writer, request requester) error {
	if ctx == nil {
		return errors.New("scan context is nil")
	}
	if out == nil {
		return errors.New("scan output is nil")
	}
	if request == nil {
		return errors.New("scan requester is nil")
	}
	ids := identities(base, accounts, certs)
	if len(ids) == 0 {
		_, _ = fmt.Fprintln(out, "No configured identities to scan")
		return nil
	}
	results := make(map[string]*finding)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		coverage := scanIdentity(ctx, id, request, results)
		_, _ = fmt.Fprintf(out, "Coverage: %s: %s\n", id.label, coverage)
	}
	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := results[key]
		labels := make([]string, 0, len(item.identities))
		for label := range item.identities {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		_, _ = fmt.Fprintf(out, "Finding: %s: %s [%s] readable by %s (API server %s)\n", item.location, item.kind, item.confidence, strings.Join(labels, ", "), item.server)
	}
	_, _ = fmt.Fprintf(out, "Findings: %d\n", len(results))
	return nil
}

func identities(base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair) []identity {
	var ids []identity
	seen := make(map[string]bool)
	add := func(label, key string, cfg model.ServerInfo) {
		if key == "" {
			return
		}
		if seen[key] {
			for i := range ids {
				if credentialKey(ids[i].cfg) == key {
					ids[i].label += ", " + label
					break
				}
			}
			return
		}
		seen[key] = true
		ids = append(ids, identity{label: label, cfg: cfg})
	}
	if base.Token != "" || (base.ClientCertData != "" && base.ClientKeyData != "") {
		key := credentialKey(base)
		label := "active service account"
		if base.ActiveTokenKind != "" {
			label = "active node token"
		}
		if base.ClientCertData != "" {
			label = "active certificate"
			if base.ClientCertName != "" {
				label += " " + safeLabel(base.ClientCertName)
			}
		} else if base.TokenName != "" {
			label += " " + safeLabel(base.TokenName)
		}
		add(label, key, base)
	}
	for i, account := range accounts {
		if account.Token == "" {
			continue
		}
		cfg := base
		cfg.ActiveTokenKind, cfg.ActiveTokenExpiresAt = "", time.Time{}
		cfg.Token = account.Token
		cfg.TokenName = account.Name
		cfg.ClientCertData, cfg.ClientKeyData, cfg.ClientCertName = "", "", ""
		label := "service account #" + strconv.Itoa(i+1)
		if account.Name != "" {
			label += " " + safeLabel(account.Name)
		}
		add(label, credentialKey(cfg), cfg)
	}
	for i, cert := range certs {
		if cert.ClientCertificateData == "" || cert.ClientKeyData == "" {
			continue
		}
		cfg := base
		cfg.ActiveTokenKind, cfg.ActiveTokenExpiresAt = "", time.Time{}
		cfg.Token, cfg.TokenName = "", ""
		cfg.ClientCertData, cfg.ClientKeyData, cfg.ClientCertName = cert.ClientCertificateData, cert.ClientKeyData, cert.Name
		if cert.APIServer != "" {
			cfg.APIServer = cert.APIServer
		}
		if cert.CACert != "" {
			cfg.CACertData = cert.CACert
			cfg.CAPath = ""
		}
		label := "certificate #" + strconv.Itoa(i+1)
		if cert.Name != "" {
			label += " " + safeLabel(cert.Name)
		}
		add(label, credentialKey(cfg), cfg)
	}
	return ids
}

func credentialKey(cfg model.ServerInfo) string {
	// Length delimiters avoid ambiguous concatenation; the key never leaves memory.
	parts := []string{cfg.APIServer, cfg.Token, cfg.ClientCertData, cfg.ClientKeyData, cfg.CACertData, cfg.CAPath, strconv.FormatBool(cfg.IgnoreTLS)}
	var b strings.Builder
	for _, part := range parts {
		fmt.Fprintf(&b, "%d:%s", len(part), part)
	}
	return b.String()
}

func scanIdentity(ctx context.Context, id identity, request requester, results map[string]*finding) string {
	coverage, forbidden := scanScope(ctx, id, "", request, results)
	if forbidden && strings.TrimSpace(id.cfg.Namespace) != "" {
		local, _ := scanScope(ctx, id, strings.TrimSpace(id.cfg.Namespace), request, results)
		return "cluster list forbidden; " + local
	}
	return coverage
}

func scanScope(ctx context.Context, id identity, namespace string, request requester, results map[string]*finding) (string, bool) {
	continueToken := ""
	objects := 0
	for page := 0; page < maxPages; page++ {
		if len(results) >= maxFindings {
			return fmt.Sprintf("incomplete: finding limit reached (%d)", len(results)), false
		}
		if err := ctx.Err(); err != nil {
			return "incomplete: cancelled", false
		}
		list, err := request(ctx, id.cfg, namespace, continueToken)
		if err != nil {
			var status *statusError
			if errors.As(err, &status) && status.code == http.StatusForbidden && page == 0 && namespace == "" {
				return "cluster list forbidden", true
			}
			return "incomplete: " + errorCategory(err), false
		}
		for _, cm := range list.Items {
			if objects >= maxObjects {
				return fmt.Sprintf("incomplete: object limit reached (%d)", objects), false
			}
			objects++
			collect(id.label, id.cfg.APIServer, cm, results)
			if len(results) >= maxFindings {
				return fmt.Sprintf("incomplete: finding limit reached (%d)", len(results)), false
			}
		}
		if list.Continue == "" {
			scope := "all namespaces"
			if namespace != "" {
				scope = "namespace " + safeLabel(namespace)
			}
			return fmt.Sprintf("%s complete (%d ConfigMaps)", scope, objects), false
		}
		if list.Continue == continueToken {
			return "incomplete: repeated page cursor", false
		}
		continueToken = list.Continue
	}
	return fmt.Sprintf("incomplete: page limit reached (%d ConfigMaps)", objects), false
}

func collect(identityLabel, apiServer string, cm corev1.ConfigMap, results map[string]*finding) {
	add := func(key string, data []byte) {
		location := safeLabel(cm.Namespace) + "/" + safeLabel(cm.Name) + "/" + safeLabel(key)
		for _, match := range detect(data) {
			resultKey := apiServer + "\x00" + location + "\x00" + match.kind
			item := results[resultKey]
			if item == nil {
				if len(results) >= maxFindings {
					return
				}
				item = &finding{location: location, server: safeServerLabel(apiServer), kind: match.kind, confidence: match.confidence, identities: make(map[string]bool)}
				results[resultKey] = item
			}
			item.identities[identityLabel] = true
		}
	}
	dataKeys := make([]string, 0, len(cm.Data))
	for key := range cm.Data {
		dataKeys = append(dataKeys, key)
	}
	sort.Strings(dataKeys)
	for _, key := range dataKeys {
		add("data:"+key, []byte(cm.Data[key]))
	}
	binaryKeys := make([]string, 0, len(cm.BinaryData))
	for key := range cm.BinaryData {
		binaryKeys = append(binaryKeys, key)
	}
	sort.Strings(binaryKeys)
	for _, key := range binaryKeys {
		add("binaryData:"+key, cm.BinaryData[key])
	}
}

func safeServerLabel(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "<invalid API server>"
	}
	return safeLabel(parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath())
}

func safeLabel(value string) string {
	if len(value) > 120 {
		value = value[:120]
	}
	return strconv.QuoteToASCII(value)
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "API status " + strconv.Itoa(e.code) }

func errorCategory(err error) string {
	var status *statusError
	if errors.As(err, &status) {
		switch status.code {
		case http.StatusForbidden:
			return "forbidden"
		case http.StatusUnauthorized:
			return "unauthorized"
		case http.StatusRequestEntityTooLarge:
			return "response too large"
		default:
			return "API status " + strconv.Itoa(status.code)
		}
	}
	if errors.Is(err, errResponseTooLarge) {
		return "response too large"
	}
	if errors.Is(err, errInvalidResponse) {
		return "invalid API response"
	}
	return "transport failure"
}

var (
	errResponseTooLarge = errors.New("response too large")
	errInvalidResponse  = errors.New("invalid API response")
)

func listPage(ctx context.Context, cfg model.ServerInfo, namespace, continueToken string) (corev1.ConfigMapList, error) {
	var empty corev1.ConfigMapList
	if err := kube.CheckActiveToken(cfg); err != nil {
		return empty, err
	}
	apiURL, err := url.Parse(cfg.APIServer)
	if err != nil || (apiURL.Scheme != "https" && apiURL.Scheme != "http") || apiURL.Host == "" || apiURL.User != nil || apiURL.RawQuery != "" || apiURL.Fragment != "" {
		return empty, errInvalidResponse
	}
	segments := []string{apiURL.Path, "api", "v1"}
	if namespace != "" {
		segments = append(segments, "namespaces", url.PathEscape(namespace))
	}
	segments = append(segments, "configmaps")
	apiURL.Path = path.Join(segments...)
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(pageSize))
	if continueToken != "" {
		query.Set("continue", continueToken)
	}
	apiURL.RawQuery = query.Encode()
	config := &rest.Config{Host: cfg.APIServer, BearerToken: cfg.Token, TLSClientConfig: rest.TLSClientConfig{Insecure: cfg.IgnoreTLS, CertData: []byte(cfg.ClientCertData), KeyData: []byte(cfg.ClientKeyData)}}
	if !cfg.IgnoreTLS {
		config.CAData = []byte(cfg.CACertData)
		if cfg.CACertData == "" {
			config.CAFile = cfg.CAPath
		}
	}
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		return empty, err
	}
	client.Timeout = requestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return empty, errInvalidResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return empty, &statusError{code: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return empty, err
	}
	if len(body) > maxResponseBytes {
		return empty, errResponseTooLarge
	}
	if err := json.Unmarshal(body, &empty); err != nil {
		return corev1.ConfigMapList{}, errInvalidResponse
	}
	if empty.Kind != "" && empty.Kind != "ConfigMapList" {
		return corev1.ConfigMapList{}, errInvalidResponse
	}
	return empty, nil
}
