package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fixtureNow = time.Unix(1700000000, 0)

const validBody = `{"access_token":"fixture-secret","token_type":"Bearer","expires_on":"1700003600","client_id":"returned-client"}`

func fixtureClient(t *testing.T, handler http.HandlerFunc) *MetadataClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := NewMetadataClient()
	client.Endpoint = server.URL + "/metadata/identity/oauth2/token"
	client.Now = func() time.Time { return fixtureNow }
	t.Cleanup(client.HTTPClient.CloseIdleConnections)
	return client
}

func TestRequestTokenProtocol(t *testing.T) {
	for _, test := range []struct {
		name, parameter, value string
		request                TokenRequest
	}{
		{name: "default", request: TokenRequest{Resource: DefaultResource}},
		{name: "client", parameter: "client_id", value: "client+&?", request: TokenRequest{Resource: "api://resource/path?a=1&b=2", ClientID: "client+&?"}},
		{name: "object", parameter: "object_id", value: "object", request: TokenRequest{Resource: DefaultResource, ObjectID: "object"}},
		{name: "resource", parameter: "msi_res_id", value: "/subscriptions/test/identities/test", request: TokenRequest{Resource: DefaultResource, MSIResourceID: "/subscriptions/test/identities/test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/metadata/identity/oauth2/token" || r.Header.Get("Metadata") != "true" {
					t.Errorf("unexpected request: %s %s %v", r.Method, r.URL.Path, r.Header)
				}
				q := r.URL.Query()
				if q.Get("api-version") != "2018-02-01" || q.Get("resource") != test.request.Resource {
					t.Errorf("query = %v", q)
				}
				for _, name := range []string{"client_id", "object_id", "msi_res_id"} {
					want := ""
					if name == test.parameter {
						want = test.value
					}
					if q.Get(name) != want {
						t.Errorf("%s = %q, want %q", name, q.Get(name), want)
					}
				}
				fmt.Fprint(w, validBody)
			})
			token, err := client.RequestToken(context.Background(), test.request)
			if err != nil || calls.Load() != 1 || token.AccessToken != "fixture-secret" || token.ClientID != "returned-client" || token.Resource != test.request.Resource || !token.ExpiresOn.Equal(fixtureNow.Add(time.Hour)) {
				t.Fatalf("token=%+v calls=%d err=%v", token, calls.Load(), err)
			}
		})
	}
}

func TestRequestTokenInvalidResponses(t *testing.T) {
	for _, test := range []struct{ name, body, want string }{
		{"malformed", "{", "malformed"},
		{"resource mismatch", strings.Replace(validBody, `"client_id"`, `"resource":"https://other.example/","client_id"`, 1), "different resource"},
		{"trailing", validBody + "{}", "malformed"},
		{"missing token", `{"token_type":"Bearer","expires_on":"1700003600"}`, "nonempty bearer"},
		{"blank token", `{"access_token":" ","token_type":"Bearer"}`, "nonempty bearer"},
		{"wrong token type", strings.Replace(validBody, "Bearer", "Basic", 1), "nonempty bearer"},
		{"missing expiry", `{"access_token":"secret","token_type":"Bearer"}`, "expires_on"},
		{"bad expiry", strings.Replace(validBody, "1700003600", "tomorrow", 1), "expires_on"},
		{"fraction expiry", strings.Replace(validBody, `"1700003600"`, "1700003600.5", 1), "expires_on"},
		{"overflow expiry", strings.Replace(validBody, "1700003600", "9223372036854775808", 1), "expires_on"},
		{"expired", strings.Replace(validBody, "1700003600", "1699999999", 1), "expired"},
		{"equal now", strings.Replace(validBody, "1700003600", "1700000000", 1), "expired"},
		{"oversized", strings.Repeat("x", maxResponseBytes+1), "1 MiB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, test.body) })
			token, err := client.RequestToken(context.Background(), TokenRequest{Resource: DefaultResource})
			if err == nil || !strings.Contains(err.Error(), test.want) || token.AccessToken != "" {
				t.Fatalf("token=%+v err=%v", token, err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("error exposed token")
			}
		})
	}
}

func TestRequestTokenNumericExpiry(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Replace(validBody, `"1700003600"`, "1700003600", 1))
	})
	if _, err := client.RequestToken(context.Background(), TokenRequest{Resource: DefaultResource}); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTokenHTTPErrorAndRedirect(t *testing.T) {
	for _, status := range []int{400, 403, 404, 429, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":"invalid_request","error_description":"select an identity","access_token":"do-not-echo"}`)
			})
			_, err := client.RequestToken(context.Background(), TokenRequest{Resource: DefaultResource})
			var imdsErr *HTTPError
			if !errors.As(err, &imdsErr) || imdsErr.StatusCode != status || imdsErr.Code != "invalid_request" || imdsErr.Description != "select an identity" || calls.Load() != 1 {
				t.Fatalf("calls=%d error=%v", calls.Load(), err)
			}
			if strings.Contains(err.Error(), "do-not-echo") {
				t.Fatal("raw error body exposed")
			}
		})
	}
}

func TestRequestTokenInvalidSelections(t *testing.T) {
	var calls atomic.Int32
	client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) })
	for _, request := range []TokenRequest{{}, {Resource: " "}, {Resource: DefaultResource, ClientID: "a", ObjectID: "b"}, {Resource: DefaultResource, ObjectID: "a", MSIResourceID: "b"}, {Resource: DefaultResource, ClientID: " "}} {
		if _, err := client.RequestToken(context.Background(), request); err == nil {
			t.Errorf("accepted %+v", request)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("made %d invalid requests", calls.Load())
	}
}

func TestRequestTokenCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name      string
		timeout   time.Duration
		cancelled bool
	}{
		{"cancelled", 0, true}, {"caller deadline", 20 * time.Millisecond, false}, {"overall deadline", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() })
			ctx := context.Background()
			cancel := func() {}
			if test.cancelled {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else if test.timeout != 0 {
				ctx, cancel = context.WithTimeout(ctx, test.timeout)
			}
			defer cancel()
			started := time.Now()
			_, err := client.RequestToken(ctx, TokenRequest{Resource: DefaultResource})
			if err == nil {
				t.Fatal("expected cancellation")
			}
			if test.cancelled && calls.Load() != 0 {
				t.Fatal("cancelled context made request")
			}
			if time.Since(started) > 6*time.Second {
				t.Fatal("request exceeded bounded timeout")
			}
			if !test.cancelled && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline: %v", err)
			}
		})
	}
}

func TestMetadataTransportBypassesProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { proxyCalls.Add(1); w.WriteHeader(500) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, validBody) })
	transport, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.HTTPClient.Timeout != 5*time.Second {
		t.Fatal("metadata transport is not direct and bounded")
	}
	if _, err := client.RequestToken(context.Background(), TokenRequest{Resource: DefaultResource}); err != nil {
		t.Fatal(err)
	}
	if proxyCalls.Load() != 0 {
		t.Fatal("proxy contacted")
	}
}
