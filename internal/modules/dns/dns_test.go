package dns

import (
	"errors"
	"net"
	"testing"
)

func TestServices(t *testing.T) {
	resolver := Resolver{
		LookupSRV: func(_, _, name string) (string, []*net.SRV, error) {
			if name != "any.any.svc.cluster.local" {
				t.Fatalf("name = %q", name)
			}
			return "", []*net.SRV{{Target: "api.default.svc.cluster.local.", Port: 443}}, nil
		},
		LookupHost: func(host string) ([]string, error) {
			return []string{"10.0.0.1"}, nil
		},
	}
	got, err := resolver.Services()
	if err != nil || len(got) != 1 || got[0].IP != "10.0.0.1" || got[0].Port != 443 {
		t.Fatalf("Services() = %#v, %v", got, err)
	}
}

func TestServicesSkipsFailedHostAndReturnsSRVError(t *testing.T) {
	resolver := Resolver{
		LookupSRV: func(string, string, string) (string, []*net.SRV, error) {
			return "", []*net.SRV{{Target: "missing", Port: 80}}, nil
		},
		LookupHost: func(string) ([]string, error) { return nil, errors.New("missing") },
	}
	got, err := resolver.Services()
	if err != nil || len(got) != 0 {
		t.Fatalf("Services() = %#v, %v", got, err)
	}
	want := errors.New("dns unavailable")
	resolver.LookupSRV = func(string, string, string) (string, []*net.SRV, error) { return "", nil, want }
	if _, err := resolver.Services(); !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}
