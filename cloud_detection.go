package peirates

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

var hc = &http.Client{Timeout: 300 * time.Millisecond}

type CloudProvider struct {
	Name              string
	URL               string
	HTTPMethod        string
	CustomHeader      string
	CustomHeaderValue string
	ResultString      string
}

func populateAndCheckCloudProviders() string {
	providers := []CloudProvider{
		{
			Name:              "AWS",
			URL:               "http://169.254.169.254/latest/",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "meta-data",
		},
		{
			Name:              "Azure",
			URL:               "http://169.254.169.254/metadata/instance?api-version=2024-03-15",
			HTTPMethod:        "GET",
			CustomHeader:      "Metadata",
			CustomHeaderValue: "true",
			ResultString:      "AzurePublicCloud",
		},
		{
			Name:              "Google Cloud",
			URL:               "http://metadata.google.internal/computeMetadata/",
			HTTPMethod:        "GET",
			CustomHeader:      "Metadata-Flavor",
			CustomHeaderValue: "Google",
			ResultString:      "v1/",
		},
		{
			Name:              "DigitalOcean",
			URL:               "http://169.254.169.254/metadata/v1/dns/",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "nameservers",
		},
		{
			Name:              "AWS (IMDSv2)",
			URL:               "http://169.254.169.254/latest/api/token",
			HTTPMethod:        "PUT",
			CustomHeader:      "X-aws-ec2-metadata-token-ttl-seconds",
			CustomHeaderValue: "21600",
			ResultString:      "",
		},
	}

	// Check to see if we are on a cloud provider at all before checking every single cloud provider's Metadata API.
	client := http.Client{
		Timeout: 1 * time.Second,
	}
	url := "http://169.254.169.254/"
	// IMDSv2 will return a 401 in this case
	_, err := client.Get(url)
	if err != nil {
		return "-- Public Cloud Provider not detected --"
	}

	// Now check each cloud provider's metadata API.
	for _, provider := range providers {
		checking := fmt.Sprintf("Checking if we are on %s...", provider.Name)
		printIfVerbose(checking, Verbose)

		var response string
		var statusCode int

		var lines []HeaderLine

		if provider.CustomHeader != "" {
			line := HeaderLine{LHS: provider.CustomHeader, RHS: provider.CustomHeaderValue}
			lines = append(lines, line)
			response, statusCode, err = GetRequest(provider.URL, lines, true)
		} else {
			response, statusCode, err = GetRequest(provider.URL, nil, true)
		}

		if err != nil {
			continue
		}
		if provider.Name == "AWS (IMDSv2)" {
			if statusCode == http.StatusOK {
				return provider.Name
			}
		}

		if strings.Contains(response, provider.ResultString) {
			return provider.Name
		}
	}
	return "-- Public Cloud Metadata API not detected --"
}

func detectContainer() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	fc := string(b)
	kube := strings.Contains(fc, "kube")
	container := strings.Contains(fc, "containerd")

	if kube {
		return "K8S Container"
	}

	if container {
		return "Container"
	}

	return ""
}

func detectOpenStack() string {
	if runtime.GOOS != "windows" {
		data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
		if err != nil {
			return ""
		}
		if strings.Contains(string(data), "OpenStack Foundation") {
			return "OpenStack"
		}
		return ""
	}
	return ""
}
