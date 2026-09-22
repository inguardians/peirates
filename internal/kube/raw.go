package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultRawRequestTimeout bounds requests to the Kubernetes API server.
	DefaultRawRequestTimeout = 10 * time.Second
	// DefaultRawResponseLimit bounds successful arbitrary-byte responses.
	DefaultRawResponseLimit int64 = 1 << 20
	// DefaultRawErrorBodyLimit bounds details retained from unsuccessful responses.
	DefaultRawErrorBodyLimit int64 = 4 << 10
)

// ErrRawResponseTooLarge identifies a successful response that exceeded its
// configured byte limit.
var ErrRawResponseTooLarge = errors.New("kubernetes API response exceeds configured limit")

// RawRequestOptions describes one bounded request to the configured API server.
type RawRequestOptions struct {
	Method            string
	APIPath           string
	Body              []byte
	ContentType       string
	Timeout           time.Duration
	MaxResponseBytes  int64
	MaxErrorBodyBytes int64
}

// HTTPStatusError describes a non-successful Kubernetes API response. Detail
// is sanitized and bounded by RawRequestOptions.MaxErrorBodyBytes.
type HTTPStatusError struct {
	StatusCode      int
	Status          string
	Detail          string
	DetailTruncated bool
	DetailReadError error
}

func (e *HTTPStatusError) Error() string {
	message := fmt.Sprintf("kubernetes API returned %s", e.Status)
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	if e.DetailTruncated {
		message += " (detail truncated)"
	}
	if e.DetailReadError != nil {
		message += fmt.Sprintf(" (detail read failed: %v)", e.DetailReadError)
	}
	return message
}

// Unwrap exposes an error encountered while reading a non-successful response
// body while preserving HTTPStatusError for status-code classification.
func (e *HTTPStatusError) Unwrap() error { return e.DetailReadError }

// RawRequest sends one bounded arbitrary-byte request to the Kubernetes API
// server using the credentials and TLS configuration in cfg.
func RawRequest(ctx context.Context, cfg ServerInfo, options RawRequestOptions) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("kubernetes API request context is nil")
	}
	if options.Method == "" {
		return nil, errors.New("kubernetes API request method is empty")
	}
	if options.Timeout <= 0 {
		return nil, errors.New("kubernetes API request timeout must be positive")
	}
	if err := validateRawLimit("response", options.MaxResponseBytes); err != nil {
		return nil, err
	}
	if err := validateRawLimit("error body", options.MaxErrorBodyBytes); err != nil {
		return nil, err
	}

	requestURL, err := rawRequestURL(cfg.APIServer, options.APIPath)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, options.Method, requestURL, bytes.NewReader(options.Body))
	if err != nil {
		return nil, fmt.Errorf("build kubernetes API request: %w", err)
	}
	request.Header.Set("Accept", "*/*")
	if options.ContentType != "" {
		request.Header.Set("Content-Type", options.ContentType)
	}
	if cfg.Token != "" {
		request.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	transport, err := rawTransport(cfg, request.URL.Scheme)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform kubernetes API request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, rawStatusError(response, options.MaxErrorBodyBytes, cfg.Token)
	}
	content, err := readBounded(response.Body, options.MaxResponseBytes)
	if err != nil {
		if errors.Is(err, ErrRawResponseTooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("read kubernetes API response: %w", err)
	}
	return content, nil
}

func validateRawLimit(name string, limit int64) error {
	if limit <= 0 || limit == math.MaxInt64 {
		return fmt.Errorf("kubernetes API %s limit must be positive and bounded", name)
	}
	return nil
}

func rawRequestURL(server, apiPath string) (string, error) {
	base, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("parse kubernetes API server URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", errors.New("kubernetes API server URL must use http or https")
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", errors.New("kubernetes API server URL must contain only an origin and optional base path")
	}
	if hasDotPathSegment(base.Path) {
		return "", errors.New("kubernetes API server base path contains a dot segment")
	}

	reference, err := url.Parse(apiPath)
	if err != nil {
		return "", fmt.Errorf("parse kubernetes API path: %w", err)
	}
	if reference.IsAbs() || reference.Host != "" || reference.User != nil || reference.RawQuery != "" || reference.Fragment != "" {
		return "", errors.New("kubernetes API path must be a path without an origin, query, or fragment")
	}
	if reference.Path == "" {
		return "", errors.New("kubernetes API path is empty")
	}
	if hasDotPathSegment(reference.Path) {
		return "", errors.New("kubernetes API path contains a dot segment")
	}

	baseEscapedPath := strings.TrimRight(base.EscapedPath(), "/")
	referenceEscapedPath := strings.TrimLeft(reference.EscapedPath(), "/")
	joinedEscapedPath := baseEscapedPath + "/" + referenceEscapedPath
	joinedPath, err := url.PathUnescape(joinedEscapedPath)
	if err != nil {
		return "", fmt.Errorf("decode kubernetes API path: %w", err)
	}
	base.Path = joinedPath
	base.RawPath = joinedEscapedPath
	return base.String(), nil
}

func hasDotPathSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func rawTransport(cfg ServerInfo, scheme string) (*http.Transport, error) {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if scheme != "https" {
		if cfg.ClientCertData != "" || cfg.ClientKeyData != "" {
			if _, err := rawClientCertificate(cfg); err != nil {
				return nil, err
			}
		}
		return transport, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.IgnoreTLS {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- explicitly selected by the operator through ServerInfo.IgnoreTLS.
	} else {
		roots, err := rawRootCAs(cfg)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = roots
	}
	certificate, err := rawClientCertificate(cfg)
	if err != nil {
		return nil, err
	}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func rawRootCAs(cfg ServerInfo) (*x509.CertPool, error) {
	if cfg.CACertData == "" && cfg.CAPath == "" {
		return nil, errors.New("certificate authority not configured for kubernetes API server")
	}
	pool := x509.NewCertPool()
	if cfg.CACertData != "" && !pool.AppendCertsFromPEM([]byte(cfg.CACertData)) {
		return nil, errors.New("parse kubernetes API certificate authority data")
	}
	if cfg.CAPath != "" {
		certificate, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read kubernetes API certificate authority file: %w", err)
		}
		if !pool.AppendCertsFromPEM(certificate) {
			return nil, errors.New("parse kubernetes API certificate authority file")
		}
	}
	return pool, nil
}

func rawClientCertificate(cfg ServerInfo) (*tls.Certificate, error) {
	if cfg.ClientCertData == "" && cfg.ClientKeyData == "" {
		return nil, nil
	}
	if cfg.ClientCertData == "" || cfg.ClientKeyData == "" {
		return nil, errors.New("both kubernetes API client certificate and key are required")
	}
	certificate, err := tls.X509KeyPair([]byte(cfg.ClientCertData), []byte(cfg.ClientKeyData))
	if err != nil {
		return nil, fmt.Errorf("parse kubernetes API client certificate and key: %w", err)
	}
	return &certificate, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, ErrRawResponseTooLarge
	}
	return content, nil
}

func rawStatusError(response *http.Response, limit int64, token string) error {
	detail, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	truncated := int64(len(detail)) > limit
	if truncated {
		detail = detail[:limit]
	}
	sanitized, sanitizedTruncated := sanitizeErrorDetail(detail, token, limit)
	status := fmt.Sprintf("%d", response.StatusCode)
	if text := http.StatusText(response.StatusCode); text != "" {
		status += " " + text
	}
	return &HTTPStatusError{
		StatusCode:      response.StatusCode,
		Status:          status,
		Detail:          sanitized,
		DetailTruncated: truncated || sanitizedTruncated,
		DetailReadError: err,
	}
}

func sanitizeErrorDetail(value []byte, token string, limit int64) (string, bool) {
	valid := strings.ToValidUTF8(string(value), "�")
	var sanitized strings.Builder
	for _, character := range valid {
		if unicode.IsControl(character) && !unicode.IsSpace(character) {
			sanitized.WriteRune('�')
			continue
		}
		sanitized.WriteRune(character)
	}
	detail := strings.Join(strings.Fields(sanitized.String()), " ")
	if token != "" {
		detail = strings.ReplaceAll(detail, token, "[REDACTED]")
	}
	if int64(len(detail)) <= limit {
		return detail, false
	}
	bounded := []byte(detail)[:int(limit)]
	for len(bounded) > 0 && !utf8.Valid(bounded) {
		bounded = bounded[:len(bounded)-1]
	}
	return string(bounded), true
}

// NodeProxyLogPath returns the API-server path for the kubelet system-log
// proxy, escaping the node and every supplied log path component independently.
func NodeProxyLogPath(node string, components ...string) (string, error) {
	if node == "" || node == "." || node == ".." {
		return "", errors.New("Kubernetes node name is empty or invalid")
	}
	path := "/api/v1/nodes/" + url.PathEscape(node) + "/proxy/logs/"
	escaped := make([]string, len(components))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return "", errors.New("kubelet log path component is empty or invalid")
		}
		escaped[index] = url.PathEscape(component)
	}
	return path + strings.Join(escaped, "/"), nil
}
