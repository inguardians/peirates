package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/instance/service-accounts/default/token" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Fatalf("header = %q", got)
		}
		_, _ = w.Write([]byte(`{"access_token":"token...","expires_in":60,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	now := time.Unix(100, 0)
	client := MetadataClient{BaseURL: server.URL, Client: server.Client(), Now: func() time.Time { return now }}
	token, expiration, err := client.BearerToken("default")
	if err != nil || token != "token" || !expiration.Equal(now.Add(60)) {
		t.Fatalf("BearerToken() = %q, %v, %v", token, expiration, err)
	}
}

func TestBearerTokenRejectsBadResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := MetadataClient{BaseURL: server.URL, Client: server.Client(), Now: time.Now}
	if _, _, err := client.BearerToken("default"); err == nil {
		t.Fatal("BearerToken succeeded")
	}
}
