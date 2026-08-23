package app

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func useGCPRequest(t *testing.T, fn func(string, []HeaderLine, bool) (string, int, error)) {
	t.Helper()
	oldBaseURL, oldGetRequest := gcpMetadataBaseURL, gcpGetRequest
	gcpMetadataBaseURL, gcpGetRequest = "http://metadata.test/computeMetadata/v1", fn
	t.Cleanup(func() {
		gcpMetadataBaseURL, gcpGetRequest = oldBaseURL, oldGetRequest
	})
}

func TestGetGCPBearerTokenFromMetadataAPI(t *testing.T) {
	useGCPRequest(t, func(url string, headers []HeaderLine, insecure bool) (string, int, error) {
		if url != "http://metadata.test/computeMetadata/v1/instance/service-accounts/default/token" {
			t.Errorf("URL = %q", url)
		}
		if insecure || len(headers) != 1 || headers[0] != (HeaderLine{"Metadata-Flavor", "Google"}) {
			t.Errorf("headers = %#v, insecure = %t", headers, insecure)
		}
		return `{"access_token":"bearer...","expires_in":60,"token_type":"Bearer"}`, 200, nil
	})

	before := time.Now()
	token, expiration, err := GetGCPBearerTokenFromMetadataAPI("default")
	if err != nil || token != "bearer" {
		t.Fatalf("GetGCPBearerTokenFromMetadataAPI() = %q, %v, %v", token, expiration, err)
	}
	if expiration.Before(before) {
		t.Fatalf("expiration %v precedes request", expiration)
	}
}

func TestGetGCPBearerTokenFromMetadataAPIRejectsBadResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
		err  error
	}{
		{name: "request error", err: errors.New("network")},
		{name: "status", body: `{"access_token":"x","token_type":"Bearer"}`, code: 500},
		{name: "malformed JSON", body: "{", code: 200},
		{name: "wrong token type", body: `{"access_token":"x","token_type":"Basic"}`, code: 200},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useGCPRequest(t, func(string, []HeaderLine, bool) (string, int, error) {
				return test.body, test.code, test.err
			})
			_, _, err := GetGCPBearerTokenFromMetadataAPI("default")
			if err == nil {
				t.Fatal("GetGCPBearerTokenFromMetadataAPI() succeeded")
			}
		})
	}
}

func TestGetGCPBearerTokenFromMetadataAPIRejectsErrorBody(t *testing.T) {
	useGCPRequest(t, func(string, []HeaderLine, bool) (string, int, error) {
		return "ERROR: unavailable", 200, nil
	})
	_, _, err := GetGCPBearerTokenFromMetadataAPI("default")
	if err == nil || !strings.Contains(err.Error(), "could not perform request") {
		t.Fatalf("error = %v", err)
	}
}
