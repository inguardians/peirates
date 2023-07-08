package pkg

import (
	"fmt"
	"io/ioutil"
	"net/http"
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

func populateAndCheckCloudProviders() {
	providers := []CloudProvider{
		{
			Name:              "AWS",
			URL:               "http://169.254.169.254/latest/",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "Amazon Web Services",
		},
		{
			Name:              "Azure",
			URL:               "http://169.254.169.254/metadata/v1/InstanceInfo",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "Microsoft Azure",
		},
		{
			Name:              "DigitalOcean",
			URL:               "http://169.254.169.254/metadata/v1.json",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "Microsoft Azure",
		},
		{
			Name:              "Google Cloud",
			URL:               "http://metadata.google.internal/computeMetadata/v1/instance/tags",
			HTTPMethod:        "GET",
			CustomHeader:      "Metadata-Flavor",
			CustomHeaderValue: "Google",
			ResultString:      "Google Compute Engine",
		},
		{
			Name:              "SoftLayer",
			URL:               "https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/UserMetadata.txt",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "SoftLayer",
		},
		{
			Name:              "Vultr",
			URL:               "http://169.254.169.254/v1.json",
			HTTPMethod:        "GET",
			CustomHeader:      "",
			CustomHeaderValue: "",
			ResultString:      "Vultr",
		},
	}

	for _, provider := range providers {
		fmt.Printf("Checking %s...\n", provider.Name)

		// Use DoHTTPRequestAndGetBody()
		req, err := http.NewRequest(provider.HTTPMethod, provider.URL, nil)
		if err != nil {
			fmt.Printf("Failed to create request for %s: %v\n", provider.Name, err)
			continue
		}

		if provider.CustomHeader != "" {
			req.Header.Set(provider.CustomHeader, provider.CustomHeaderValue)
		}

		// use DoHTTPRequestAndGetBody
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Failed to make request to %s: %v\n", provider.Name, err)
			continue
		}
		defer resp.Body.Close()

		// Use DoHTTPRequestAndGetBody()
		if resp.StatusCode == http.StatusOK {
			// Check if there's a body string returned that matches ResultString
		} else {
			fmt.Printf("%s responded with HTTP %d\n", provider.Name, resp.StatusCode)
		}
	}
}

func detectContainer() string {
	b, err := ioutil.ReadFile("/proc/self/cgroup")
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
		data, err := ioutil.ReadFile("/sys/class/dmi/id/sys_vendor")
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
