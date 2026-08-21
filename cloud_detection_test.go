package peirates

import "testing"

func TestMetadataClientHasBoundedTimeout(t *testing.T) {
	if hc == nil || hc.Timeout <= 0 {
		t.Fatalf("metadata client is not bounded: %#v", hc)
	}
}

func TestCloudProviderDefinition(t *testing.T) {
	p := CloudProvider{Name: "test", URL: "http://example.test", HTTPMethod: "GET", CustomHeader: "X-Test", CustomHeaderValue: "yes", ResultString: "ok"}
	if p.Name != "test" || p.CustomHeaderValue != "yes" {
		t.Fatalf("unexpected provider: %#v", p)
	}
}

func TestLocalEnvironmentDetectionReturnsKnownValues(t *testing.T) {
	if got := detectContainer(); got != "" && got != "Container" && got != "K8S Container" {
		t.Fatalf("unexpected container detection %q", got)
	}
	if got := detectOpenStack(); got != "" && got != "OpenStack" {
		t.Fatalf("unexpected OpenStack detection %q", got)
	}
}
