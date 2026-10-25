package kube

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrNodeTokenTargetUnavailable means generation can proceed without verification.
var ErrNodeTokenTargetUnavailable = errors.New("node token target is unavailable")

// ErrNodeTokenTargetMismatch identifies conflicting explicit and in-cluster trust.
var ErrNodeTokenTargetMismatch = errors.New("node token target conflicts with in-cluster connection")

// CheckActiveToken prevents an expired generated credential from being used or
// replaced implicitly by ambient authentication.
func CheckActiveToken(cfg ServerInfo) error {
	if cfg.ActiveTokenKind != "" && (cfg.Token == "" || cfg.ActiveTokenExpiresAt.IsZero() || !time.Now().Before(cfg.ActiveTokenExpiresAt)) {
		return errors.New("active node token is expired or unavailable; rerun aws-get-eks-node-token")
	}
	return nil
}

// ResolveNodeTokenTarget returns a copy of the target with trusted CA data loaded.
// It never loads a pod token or invokes a kubeconfig credential plugin.
func ResolveNodeTokenTarget(cfg ServerInfo) (ServerInfo, error) {
	return resolveNodeTokenTarget(cfg, os.Getenv, os.ReadFile, ServiceAccountPath)
}

func resolveNodeTokenTarget(cfg ServerInfo, getenv func(string) string, readFile func(string) ([]byte, error), podPath string) (ServerInfo, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	podEndpoint := ""
	if host != "" {
		if port == "" {
			port = "443"
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 || strings.ContainsAny(host, "/@?# \t\r\n") {
			return cfg, errors.New("invalid in-cluster API service address")
		}
		podEndpoint = "https://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if cfg.APIServer == "" || cfg.APIServer == "https://:" {
		cfg.APIServer = podEndpoint
	}
	if cfg.APIServer == "" {
		return cfg, fmt.Errorf("%w: API server is not configured", ErrNodeTokenTargetUnavailable)
	}
	if _, err := nodeTokenEndpoint(cfg.APIServer); err != nil {
		return cfg, err
	}
	if cfg.Namespace == "" {
		if data, err := readFile(podPath + "namespace"); err == nil && len(data) <= 4096 {
			cfg.Namespace = strings.TrimSpace(string(data))
		}
	}
	configuredCA := []byte(cfg.CACertData)
	if cfg.CAPath != "" {
		data, err := readFile(cfg.CAPath)
		if err != nil {
			return cfg, fmt.Errorf("%w: cannot read configured CA file", ErrNodeTokenTargetUnavailable)
		}
		if _, err := nodeTokenCAs(data); err != nil {
			return cfg, err
		}
		if len(configuredCA) != 0 && !sameNodeTokenCAs(configuredCA, data) {
			return cfg, fmt.Errorf("%w: configured CA file and data differ", ErrNodeTokenTargetMismatch)
		}
		configuredCA = data
	}
	if len(configuredCA) > 0 {
		if _, err := nodeTokenCAs(configuredCA); err != nil {
			return cfg, err
		}
	}
	podCA, podCAErr := readFile(podPath + "ca.crt")
	if podEndpoint != "" && podCAErr == nil {
		if _, err := nodeTokenCAs(podCA); err != nil {
			return cfg, errors.New("invalid in-cluster certificate authority")
		}
		if len(configuredCA) > 0 && !sameNodeTokenCAs(configuredCA, podCA) {
			return cfg, fmt.Errorf("%w: configured and pod CAs differ", ErrNodeTokenTargetMismatch)
		}
		if len(configuredCA) == 0 {
			// A CA from the pod may only fill trust for its own endpoint.
			if !sameNodeTokenEndpoint(cfg.APIServer, podEndpoint) {
				return cfg, fmt.Errorf("%w: explicit endpoint has no corroborating CA", ErrNodeTokenTargetMismatch)
			}
			configuredCA = podCA
			cfg.CAPath = podPath + "ca.crt"
		}
	} else if podEndpoint != "" && !sameNodeTokenEndpoint(cfg.APIServer, podEndpoint) {
		return cfg, fmt.Errorf("%w: cannot corroborate explicit endpoint with pod CA", ErrNodeTokenTargetMismatch)
	}
	cfg.CACertData = string(configuredCA)
	if len(configuredCA) == 0 && !cfg.IgnoreTLS {
		return cfg, fmt.Errorf("%w: certificate authority is not configured", ErrNodeTokenTargetUnavailable)
	}
	return cfg, nil
}

func nodeTokenEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("node token verification requires an HTTPS API origin without credentials, query, or path")
	}
	return u, nil
}

func sameNodeTokenEndpoint(a, b string) bool {
	first, err := nodeTokenEndpoint(a)
	if err != nil {
		return false
	}
	second, err := nodeTokenEndpoint(b)
	if err != nil {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	return strings.EqualFold(first.Hostname(), second.Hostname()) && port(first) == port(second)
}

func nodeTokenCAs(data []byte) (map[string]bool, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("node token CA exceeds size limit")
	}
	certs := make(map[string]bool)
	for len(strings.TrimSpace(string(data))) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid node token certificate authority")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid node token certificate authority")
		}
		certs[string(cert.Raw)] = true
		data = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("empty node token certificate authority")
	}
	return certs, nil
}

func sameNodeTokenCAs(a, b []byte) bool {
	first, err := nodeTokenCAs(a)
	if err != nil {
		return false
	}
	second, err := nodeTokenCAs(b)
	if err != nil || len(first) != len(second) {
		return false
	}
	for cert := range first {
		if !second[cert] {
			return false
		}
	}
	return true
}

// NodeTokenIdentity is the identity returned by Kubernetes, not decoded from a token.
type NodeTokenIdentity struct {
	Username string
	Groups   []string
}

// VerifyNodeToken inspects only the supplied token with SelfSubjectReview.
func VerifyNodeToken(ctx context.Context, cfg ServerInfo, token string) (NodeTokenIdentity, error) {
	var identity NodeTokenIdentity
	if _, err := nodeTokenEndpoint(cfg.APIServer); err != nil {
		return identity, err
	}
	if !strings.HasPrefix(token, "k8s-aws-v1.") || strings.ContainsAny(token, " \t\r\n") {
		return identity, errors.New("invalid EKS node token")
	}
	cfg.Token = token
	cfg.ClientCertData, cfg.ClientKeyData, cfg.ClientCertName = "", "", ""
	cfg.ActiveTokenKind, cfg.ActiveTokenExpiresAt = "", time.Time{}
	body, err := RawRequest(ctx, cfg, RawRequestOptions{
		Method: http.MethodPost, APIPath: "/apis/authentication.k8s.io/v1/selfsubjectreviews",
		Body:        []byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","spec":{}}`),
		ContentType: "application/json", Timeout: 10 * time.Second,
		MaxResponseBytes: 64 << 10, MaxErrorBodyBytes: 1024,
	})
	if err != nil {
		var status *HTTPStatusError
		if errors.As(err, &status) {
			switch status.StatusCode {
			case http.StatusUnauthorized:
				return identity, errors.New("node token authentication rejected (HTTP 401)")
			case http.StatusForbidden:
				return identity, errors.New("node identity inspection denied (HTTP 403); identity is unverified")
			case http.StatusNotFound, http.StatusMethodNotAllowed:
				return identity, errors.New("SelfSubjectReview is unavailable; node identity is unverified")
			default:
				return identity, fmt.Errorf("node identity inspection failed (HTTP %d)", status.StatusCode)
			}
		}
		return identity, errors.New("node identity inspection failed: transport, TLS, timeout, or response-limit error")
	}
	var response struct {
		Status struct {
			UserInfo struct {
				Username string   `json:"username"`
				Groups   []string `json:"groups"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return identity, errors.New("invalid SelfSubjectReview response")
	}
	identity.Username, identity.Groups = response.Status.UserInfo.Username, response.Status.UserInfo.Groups
	node := strings.TrimPrefix(identity.Username, "system:node:")
	if node == identity.Username || node == "" || strings.ContainsAny(node, " \t\r\n/:") {
		return identity, errors.New("authenticated identity is not a Kubernetes node")
	}
	for _, group := range identity.Groups {
		if group == "system:nodes" {
			return identity, nil
		}
	}
	return identity, errors.New("authenticated identity lacks system:nodes membership")
}
