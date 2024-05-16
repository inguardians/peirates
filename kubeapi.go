// Unused - we may use this if and when we need to make HTTP raw (non-library-based) requests, but we should
// combine this with our HTTP connection libraries.

package peirates

import (
	"fmt"
	"net/http"
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
