// Unused - we may use this if and when we need to make HTTP raw (non-library-based) requests, but we should
// combine this with our HTTP connection libraries.

package app

import (
	"fmt"
	"net/http"
)

// RequestConfig configures a raw Kubernetes API request.
type RequestConfig struct {
	Host              string
	Port              int
	Method            string
	HTTPS             bool
	IgnoreHTTPSErrors bool
}

func newKubeRequest(path string, cfg RequestConfig) (*http.Request, error) {
	var protocol string

	if cfg.HTTPS {
		protocol = "https"
	} else {
		protocol = "http"
	}

	return http.NewRequest(cfg.Method, fmt.Sprintf("%s://%s:%d/%s", protocol, cfg.Host, cfg.Port, path), nil)
}
