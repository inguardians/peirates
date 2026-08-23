package cloud

import (
	"net/http"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	detector := NewDetector(false)
	if detector.Client == nil || detector.Client.Timeout != time.Second {
		t.Fatalf("client = %#v", detector.Client)
	}
	providers := Providers()
	if len(providers) != 5 || providers[0].Name != "AWS" || providers[4].HTTPMethod != http.MethodPut {
		t.Fatalf("providers = %#v", providers)
	}
}

func TestLocalEnvironmentDetectionReturnsKnownValues(t *testing.T) {
	if got := DetectContainer(); got != "" && got != "Container" && got != "K8S Container" {
		t.Fatalf("container = %q", got)
	}
	if got := DetectOpenStack(); got != "" && got != "OpenStack" {
		t.Fatalf("OpenStack = %q", got)
	}
}
