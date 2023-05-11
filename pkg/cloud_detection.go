package pkg

import (
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

var hc = &http.Client{Timeout: 300 * time.Millisecond}

type Clouds struct {
	Aws       string
	Azure     string
	Do        string
	Gce       string
	Ost       string
	Sl        string
	Vr        string
	Container string
}

func Detect() string {
	if runtime.GOOS != "darwin" {
		var c Clouds
		var wg sync.WaitGroup
		wg.Add(8)
		go func() {
			defer wg.Done()
			c.Aws = detectAWS()
		}()
		go func() {
			defer wg.Done()
			c.Azure = detectAzure()
		}()
		go func() {
			defer wg.Done()
			c.Do = detectDigitalOcean()
		}()
		go func() {
			defer wg.Done()
			c.Gce = detectGCE()
		}()
		go func() {
			defer wg.Done()
			c.Ost = detectOpenStack()
		}()
		go func() {
			defer wg.Done()
			c.Sl = detectSoftlayer()
		}()
		go func() {
			defer wg.Done()
			c.Vr = detectVultr()
		}()
		go func() {
			defer wg.Done()
			c.Container = detectContainer()
		}()
		wg.Wait()

		if c.Aws != "" {
			return c.Aws
		}
		if c.Azure != "" {
			return c.Azure
		}
		if c.Do != "" {
			return c.Do
		}
		if c.Gce != "" {
			return c.Gce
		}
		if c.Ost != "" {
			return c.Ost
		}
		if c.Sl != "" {
			return c.Sl
		}
		if c.Vr != "" {
			return c.Vr
		}
		if c.Container != "" {
			return c.Container
		}
	}
	return ""
}

func detectAWS() string {
	resp, err := hc.Get("http://169.254.169.254/latest/")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Amazon Web Services"
	}
	return ""
}

func detectAzure() string {
	resp, err := hc.Get("http://169.254.169.254/metadata/v1/InstanceInfo")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Microsoft Azure"
	}
	return ""
}

func detectDigitalOcean() string {
	resp, err := hc.Get("http://169.254.169.254/metadata/v1.json")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Digital Ocean"
	}
	return ""
}

func detectGCE() string {
	r, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/tags", nil)
	if err != nil {
		return ""
	}
	r.Header.Add("Metadata-Flavor", "Google")
	resp, err := hc.Do(r)
	if err != nil {
		return ""
	}
	if resp.StatusCode == http.StatusOK {
		return "Google Compute Engine"
	}
	return ""
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

func detectSoftlayer() string {
	resp, err := hc.Get("https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/UserMetadata.txt")
	if err == nil && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound) {
		return "SoftLayer"
	}
	return ""
}

func detectVultr() string {
	resp, err := hc.Get("http://169.254.169.254/v1.json")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Vultr"
	}
	return ""
}
