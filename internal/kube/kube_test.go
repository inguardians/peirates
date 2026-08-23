package kube

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func stubClient(allowed bool, response []byte, responseErr error) (*Client, *[][]string) {
	var calls [][]string
	client := &Client{
		APIRequest: func(_ ServerInfo, _, _ string, _, response any) error {
			if result, ok := response.(*struct {
				Status struct {
					Allowed bool `json:"allowed"`
				} `json:"status"`
			}); ok {
				result.Status.Allowed = allowed
			}
			return nil
		},
		RunCommand: func(_ io.Reader, stdout, _ io.Writer, args ...string) error {
			calls = append(calls, args)
			_, _ = stdout.Write(response)
			return responseErr
		},
	}
	return client, &calls
}

func TestNewRequest(t *testing.T) {
	request, err := NewRequest("api/v1/pods", RequestConfig{Host: "127.0.0.1", Port: 8443, Method: http.MethodGet, HTTPS: true})
	if err != nil || request.URL.String() != "https://127.0.0.1:8443/api/v1/pods" {
		t.Fatalf("request = %v, %v", request.URL, err)
	}
}

func TestRunWithConfigValidationAndArguments(t *testing.T) {
	client, calls := stubClient(true, nil, nil)
	if err := client.RunWithConfig(ServerInfo{}, strings.NewReader(""), io.Discard, io.Discard, "get", "pods"); err == nil || err.Error() != "api server not set" {
		t.Fatalf("unexpected error %v", err)
	}
	cfg := ServerInfo{APIServer: "https://api", IgnoreTLS: true, Namespace: "ns", Token: "token"}
	if _, _, err := client.Run(cfg, "get", "pods"); err != nil {
		t.Fatal(err)
	}
	want := []string{"--server=https://api", "--insecure-skip-tls-verify=true", "-n", "ns", "--token=token", "get", "pods"}
	if !reflect.DeepEqual((*calls)[0], want) {
		t.Fatalf("args = %#v, want %#v", (*calls)[0], want)
	}
}

func TestCredentials(t *testing.T) {
	var accounts []ServiceAccount
	if !AddServiceAccount(" default ", "token", "test", &accounts) || AddServiceAccount("default", "other", "test", &accounts) {
		t.Fatal("service-account uniqueness changed")
	}
	cfg := ServerInfo{ClientCertData: "old", ClientKeyData: "old"}
	AssignServiceAccount(accounts[0], &cfg)
	if cfg.Token != "token" || cfg.ClientCertData != "" || cfg.ClientKeyData != "" {
		t.Fatalf("cfg = %#v", cfg)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:ns:name"}`))
	if subject, err := ParseServiceAccountSubject("e30." + payload + ".sig"); err != nil || subject != "system:serviceaccount:ns:name" {
		t.Fatalf("subject = %q, %v", subject, err)
	}
}

func TestEnumeration(t *testing.T) {
	client, calls := stubClient(true, []byte(`{"items":[{"metadata":{"name":"api"}},{"metadata":{"name":"worker"}}]}`), nil)
	cfg := ServerInfo{APIServer: "https://api", IgnoreTLS: true}
	if pods := client.PodList(cfg); !reflect.DeepEqual(pods, []string{"api", "worker"}) {
		t.Fatalf("pods = %#v", pods)
	}
	if got := (*calls)[0][len((*calls)[0])-4:]; !reflect.DeepEqual(got, []string{"get", "pods", "-o", "json"}) {
		t.Fatalf("args = %#v", got)
	}

	client, _ = stubClient(true, []byte("{"), nil)
	if pods := client.PodList(cfg); len(pods) != 0 {
		t.Fatalf("malformed response produced %#v", pods)
	}
	client, _ = stubClient(true, nil, errors.New("failed"))
	if pods := client.PodList(cfg); len(pods) != 0 {
		t.Fatalf("failed response produced %#v", pods)
	}
}

func TestAuthCanIInjection(t *testing.T) {
	client, _ := stubClient(false, nil, nil)
	if client.AuthCanI(ServerInfo{}, "get", "pods") == false {
		t.Fatal("disabled check should permit")
	}
	if client.AuthCanI(ServerInfo{UseAuthCanI: true, ClientCertData: "cert"}, "get", "pods") == false {
		t.Fatal("certificate fallback should permit")
	}
}
