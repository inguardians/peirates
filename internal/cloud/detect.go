// Package cloud detects cloud metadata services and local container environments.
package cloud

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// Provider describes a cloud metadata service and how to identify it.
type Provider struct {
	Name              string
	URL               string
	HTTPMethod        string
	CustomHeader      string
	CustomHeaderValue string
	ResultString      string
}

// Detector detects the cloud provider available through a metadata service.
type Detector struct {
	Client  *http.Client
	Verbose bool
	Print   func(string)
}

// NewDetector returns a metadata service detector with the default timeout.
func NewDetector(verbose bool) Detector {
	return Detector{Client: &http.Client{Timeout: time.Second}, Verbose: verbose, Print: func(s string) { println(s) }}
}

// Providers returns the cloud metadata services that can be detected.
func Providers() []Provider {
	return []Provider{
		{Name: "AWS", URL: "http://169.254.169.254/latest/", HTTPMethod: http.MethodGet, ResultString: "meta-data"},
		{Name: "Azure", URL: "http://169.254.169.254/metadata/instance?api-version=2024-03-15", HTTPMethod: http.MethodGet, CustomHeader: "Metadata", CustomHeaderValue: "true", ResultString: "AzurePublicCloud"},
		{Name: "Google Cloud", URL: "http://metadata.google.internal/computeMetadata/", HTTPMethod: http.MethodGet, CustomHeader: "Metadata-Flavor", CustomHeaderValue: "Google", ResultString: "v1/"},
		{Name: "DigitalOcean", URL: "http://169.254.169.254/metadata/v1/dns/", HTTPMethod: http.MethodGet, ResultString: "nameservers"},
		{Name: "AWS (IMDSv2)", URL: "http://169.254.169.254/latest/api/token", HTTPMethod: http.MethodPut, CustomHeader: "X-aws-ec2-metadata-token-ttl-seconds", CustomHeaderValue: "21600"},
	}
}

// DetectProvider returns the detected cloud provider or a not-detected message.
func (d Detector) DetectProvider() string {
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: time.Second}
	}
	if _, err := client.Get("http://169.254.169.254/"); err != nil {
		return "-- Public Cloud Provider not detected --"
	}
	for _, provider := range Providers() {
		if d.Verbose && d.Print != nil {
			d.Print(fmt.Sprintf("Checking if we are on %s...", provider.Name))
		}
		req, err := http.NewRequest(provider.HTTPMethod, provider.URL, nil)
		if err != nil {
			continue
		}
		if provider.CustomHeader != "" {
			req.Header.Set(provider.CustomHeader, provider.CustomHeaderValue)
		}
		response, err := client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			continue
		}
		if provider.Name == "AWS (IMDSv2)" && response.StatusCode == http.StatusOK {
			return provider.Name
		}
		if strings.Contains(string(body), provider.ResultString) {
			return provider.Name
		}
	}
	return "-- Public Cloud Metadata API not detected --"
}

// DetectContainer returns the detected container environment, if any.
func DetectContainer() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	cgroup := string(b)
	if strings.Contains(cgroup, "kube") {
		return "K8S Container"
	}
	if strings.Contains(cgroup, "containerd") {
		return "Container"
	}
	return ""
}

// DetectOpenStack returns OpenStack when the host vendor indicates OpenStack.
func DetectOpenStack() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return ""
	}
	if strings.Contains(string(data), "OpenStack Foundation") {
		return "OpenStack"
	}
	return ""
}
