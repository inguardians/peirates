// Unused - we may use this if and when we need to make HTTP raw (non-library-based) requests, but we should
// combine this with our HTTP connection libraries.

package peirates

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type RequestConfig struct {
	Host              string
	Port              int
	Method            string
	Https             bool
	IgnoreHttpsErrors bool
}

func newKubeRequest(path string, cfg RequestConfig) (*http.Request, error) {
	var protocol string

	if cfg.Https {
		protocol = "https"
	} else {
		protocol = "http"
	}

	return http.NewRequest(cfg.Method, fmt.Sprintf("%s://%s:%d/%s", protocol, cfg.Host, cfg.Port, path), nil)
}

// Request takes a path such as "/pod" and requests it from an HTTP server,
// returning the full response body as a string.
//
// Functions may be optionally passed in to modify the default configuration.
// The default configuration is:
//
//	RequestConfig {
//	    Host: "127.0.0.1",
//	    Port: 6443,          // The default Kubernetes port
//	    Method: "GET",
//	    Https: true,
//	    IgnoreHttpsErrors: true,
//	}
//
// For example:
//
//	func RequestSimple(path string, host string, port int) string {
//	    // This passes a function literal (also known as a lambda or anonymous function)
//	    // to RequestPath to configure the host and port.
//	    return Request(path, func (cfg *RequestConfig) {
//	        cfg.Host = host
//	        cfg.Port = port
//	    })
//	}
func Request(path string, cfgs ...func(*RequestConfig)) (string, error) {
	cfg := RequestConfig{
		Host:              "127.0.0.1",
		Port:              6443, // The default Kubernetes port
		Method:            "GET",
		Https:             true,
		IgnoreHttpsErrors: true,
	}

	// Run all configuration functions against our config to let them change it
	for _, runCfg := range cfgs {
		runCfg(&cfg)
	}

	// Build an HTTP request from our configuration
	req, err := newKubeRequest(path, cfg)
	if err != nil {
		return "", err
	}

	// Create a transport configuration
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if cfg.IgnoreHttpsErrors {
		// Set up our copy to ignore HTTPS errors
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// HTTP client with transport configuration
	client := http.Client{
		Transport: transport,
	}

	// Actually perform the request
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// Read and return the response
	contents, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(contents), nil
}

func RequestSimple(path string, host string, port int) (string, error) {
	// This passes a function literal (also known as a lambda or anonymous function)
	// to RequestPath to configure the host and port.

	output, err := Request(path, func(cfg *RequestConfig) {
		cfg.Host = host
		cfg.Port = port
	})
	if err != nil {
		return err.Error(), err
	}

	return output, nil
}
