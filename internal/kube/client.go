package kube

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const requestTimeout = 5 * time.Second

// NewRequest constructs a raw request to a Kubernetes host and port.
func NewRequest(path string, cfg RequestConfig) (*http.Request, error) {
	protocol := "http"
	if cfg.HTTPS {
		protocol = "https"
	}
	return http.NewRequest(cfg.Method, fmt.Sprintf("%s://%s:%d/%s", protocol, cfg.Host, cfg.Port, path), nil)
}

// DoHTTPRequestAndGetBody executes req with the historical timeout and TLS behavior.
func DoHTTPRequestAndGetBody(req *http.Request, https, ignoreTLSErrors bool, caCertPath string) ([]byte, error) {
	client := &http.Client{Timeout: requestTimeout}
	if https {
		pool, err := x509.SystemCertPool()
		if err != nil && caCertPath == "" {
			return nil, err
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if caCertPath != "" {
			certificate, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, err
			}
			pool.AppendCertsFromPEM(certificate)
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: ignoreTLSErrors}} // #nosec G402 -- explicitly selected by the caller.
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("DoHTTPRequestAndGetBody failed with status %s", response.Status)
	}
	return body, nil
}

// DoAPIRequest sends a JSON request using cfg and decodes the JSON response.
func DoAPIRequest(cfg ServerInfo, method, apiPath string, query, response any) error {
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return err
	}
	remotePath := strings.TrimRight(cfg.APIServer, "/") + "/" + strings.TrimLeft(apiPath, "/")
	req, err := http.NewRequest(method, remotePath, bytes.NewReader(queryJSON))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+cfg.Token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	body, err := DoHTTPRequestAndGetBody(req, true, cfg.IgnoreTLS, cfg.CAPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, response)
}
