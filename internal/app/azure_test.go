package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inguardians/peirates/internal/cloud/azure"
	"github.com/inguardians/peirates/internal/modules"
	"github.com/inguardians/peirates/internal/ui"
)

func useAzureFixture(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	useAzureDiscoveryFixture(t, "", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{}`) }, handler)
}

func useAzureDiscoveryFixture(t *testing.T, config string, instance, token http.HandlerFunc) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure.json")
	if config != "" {
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata/instance" {
			instance(w, r)
			return
		}
		token(w, r)
	}))
	t.Cleanup(server.Close)
	previous, previousPath := azureMetadataClient, azureConfigPath
	azureMetadataClient = azure.NewMetadataClient()
	azureMetadataClient.Endpoint = server.URL
	azureMetadataClient.InstanceEndpoint = server.URL + "/metadata/instance"
	azureConfigPath = path
	t.Cleanup(func() {
		azureMetadataClient.HTTPClient.CloseIdleConnections()
		azureMetadataClient, azureConfigPath = previous, previousPath
	})
}

func writeAzureFixture(w http.ResponseWriter) {
	fmt.Fprintf(w, `{"access_token":"test-bearer-secret","token_type":"Bearer","expires_on":%d,"client_id":"resolved-client"}`, time.Now().Add(time.Hour).Unix())
}

func TestAzurePromptSelection(t *testing.T) {
	useAzureFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected token request") })
	for _, test := range []struct {
		name, input string
		want        azure.TokenRequest
	}{
		{"defaults", "\n\n", azure.TokenRequest{Resource: azure.DefaultResource}},
		{"client", "https://vault.azure.net\nclient-id\nclient\n", azure.TokenRequest{Resource: "https://vault.azure.net", ClientID: "client"}},
		{"object", "\nobject-id\nobject\n", azure.TokenRequest{Resource: azure.DefaultResource, ObjectID: "object"}},
		{"resource", "\nmsi-res-id\n/subscriptions/test/identities/id\n", azure.TokenRequest{Resource: azure.DefaultResource, MSIResourceID: "/subscriptions/test/identities/id"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := strings.NewReader(test.input + "next-menu-command\n")
			var out bytes.Buffer
			selection, err := azureTokenSelection(nil, true, input, &out)
			if err != nil || selection.TokenRequest != test.want {
				t.Fatalf("selection=%+v err=%v", selection, err)
			}
			remaining, _ := io.ReadAll(input)
			if string(remaining) != "next-menu-command\n" {
				t.Fatalf("prompt consumed following input: %q", remaining)
			}
		})
	}
}

func TestAzureInteractiveRequest(t *testing.T) {
	for _, test := range []struct{ name, input, resource, clientID string }{
		{"defaults", "\n\n", azure.DefaultResource, ""},
		{"selected", "https://vault.azure.net\nclient-id\nselected-client\n", "https://vault.azure.net", "selected-client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Query().Get("resource") != test.resource || r.URL.Query().Get("client_id") != test.clientID || r.Header.Get("Metadata") != "true" {
					t.Errorf("request query=%v header=%v", r.URL.Query(), r.Header)
				}
				writeAzureFixture(w)
			})
			session := NewSession(ServerInfo{})
			var out bytes.Buffer
			requestAzureToken(session, nil, strings.NewReader(test.input), &out)
			if calls.Load() != 1 || !strings.Contains(out.String(), "Bearer token: test-bearer-secret") {
				t.Fatalf("calls=%d output=%s", calls.Load(), out.String())
			}
			entry := session.AzureTokens[AzureTokenKey{"client_id", "resolved-client", test.resource}]
			if entry.Selection.Resource != test.resource || entry.Selection.ClientID != test.clientID {
				t.Fatalf("retained selection=%+v", entry.Selection)
			}
		})
	}
}

func TestAzureRequestNoPromptModes(t *testing.T) {
	useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) { writeAzureFixture(w) })
	for _, test := range []struct {
		name        string
		interactive bool
		args        []string
	}{
		{"noninteractive defaults", false, nil},
		{"interactive options", true, []string{"--resource", "https://vault.azure.net"}},
		{"noninteractive selector", false, []string{"--object-id", "object"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := NewSession(ServerInfo{})
			session.Interactive = test.interactive
			session.Cloud = "AWS"
			var out bytes.Buffer
			requestAzureToken(session, test.args, strings.NewReader(""), &out)
			if !strings.Contains(out.String(), "Bearer token: test-bearer-secret") || len(session.AzureTokens) != 1 {
				t.Fatalf("output=%s entries=%d", out.String(), len(session.AzureTokens))
			}
			if strings.Contains(out.String(), "Resource URI [") || strings.Contains(out.String(), "Identity [") {
				t.Fatal("unexpected prompt")
			}
			if session.Connection.Token != "" || len(session.ServiceAccounts) != 0 {
				t.Fatal("Azure token altered Kubernetes state")
			}
		})
	}
}

func TestAzureInvalidAndCancelledNeverRequest(t *testing.T) {
	var calls atomic.Int32
	useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); writeAzureFixture(w) })
	for _, test := range []struct {
		name        string
		args        []string
		input       string
		interactive bool
		want        string
	}{
		{name: "help", args: []string{"--help"}, want: "Usage:"},
		{name: "unknown option", args: []string{"--unknown"}, want: "flag provided"},
		{name: "conflict", args: []string{"--client-id", "a", "--object-id", "b"}, want: "only one"},
		{name: "list with selector", args: []string{"--list-identities", "--client-id", "a"}, want: "cannot be combined"},
		{name: "list without discovery", args: []string{"--list-identities", "--no-discovery"}, want: "cannot be combined"},
		{name: "selector as value", args: []string{"--client-id", "--object-id"}, want: "missing option value"},
		{name: "help as value", args: []string{"--resource", "--help"}, want: "missing option value"},
		{name: "missing value", args: []string{"--resource"}, want: "needs an argument"},
		{name: "empty option", args: []string{"--client-id="}, want: "nonempty"},
		{name: "positional", args: []string{"extra"}, want: "positional"},
		{name: "EOF", interactive: true, want: "cancelled"},
		{name: "second EOF", interactive: true, input: "\n", want: "cancelled"},
		{name: "control C", interactive: true, input: "\x03\n", want: "cancelled"},
		{name: "unknown identity", interactive: true, input: "\nunknown\n", want: "identity must"},
		{name: "empty identity", interactive: true, input: "\nclient-id\n\n", want: "required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := NewSession(ServerInfo{})
			session.Interactive = test.interactive
			var out bytes.Buffer
			requestAzureToken(session, test.args, strings.NewReader(test.input), &out)
			if !strings.Contains(out.String(), test.want) || len(session.AzureTokens) != 0 {
				t.Fatalf("output=%s", out.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("%d requests", calls.Load())
	}
}

func TestAzureSessionRetentionAndStatus(t *testing.T) {
	session := NewSession(ServerInfo{})
	now := time.Now().UTC().Truncate(time.Second)
	token := azure.Token{AccessToken: "first-secret", ClientID: "same-client", ExpiresOn: now.Add(time.Hour)}
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource, ClientID: "same-client"}, token)
	token.AccessToken = "second-secret"
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource, ObjectID: "object"}, token)
	if len(session.AzureTokens) != 1 {
		t.Fatal("returned client ID did not deduplicate selectors")
	}
	entry := session.AzureTokens[AzureTokenKey{"client_id", "same-client", azure.DefaultResource}]
	if entry.Token.AccessToken != "second-secret" || entry.Selection.ObjectID != "object" {
		t.Fatal("successful acquisition did not replace token and selector")
	}
	session.retainAzureToken(azure.TokenRequest{Resource: "https://vault.azure.net"}, token)
	token.ClientID = "another-client"
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource}, token)
	token.ClientID = ""
	token.ExpiresOn = now
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource}, token)
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource, ObjectID: "fallback-object"}, token)
	session.retainAzureToken(azure.TokenRequest{Resource: azure.DefaultResource, MSIResourceID: "/fallback-resource"}, token)
	if len(session.AzureTokens) != 6 {
		t.Fatalf("retained %d entries", len(session.AzureTokens))
	}
	var status bytes.Buffer
	printAzureTokenStatus(&status, session, now)
	for _, want := range []string{"Azure token (expired)", "Azure token (available)", "same-client", "another-client", "fallback-object", "/fallback-resource", "https://vault.azure.net", "default", now.Format(time.RFC3339)} {
		if !strings.Contains(status.String(), want) {
			t.Errorf("status missing %q: %s", want, status.String())
		}
	}
	if strings.Contains(status.String(), "secret") {
		t.Fatal("status exposed bearer token")
	}
	useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	session.Interactive = false
	requestAzureToken(session, nil, strings.NewReader(""), io.Discard)
	if len(session.AzureTokens) != 6 || session.AzureTokens[AzureTokenKey{"client_id", "same-client", azure.DefaultResource}].Token.AccessToken != "second-secret" {
		t.Fatal("failure changed retained tokens")
	}
}

func TestAzureDispatchAndCompletion(t *testing.T) {
	var calls atomic.Int32
	useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); writeAzureFixture(w) })
	session := NewSession(ServerInfo{})
	session.Interactive = false
	registry := newModuleRegistry(session)
	for _, alias := range []string{"36", "azure-get-token", "get-azure-token"} {
		if CanonicalCommand(alias) != "azure-get-token" {
			t.Fatalf("alias %q missing", alias)
		}
		for _, suffix := range []string{"", ` --resource 'https://vault.azure.net' --client-id "client"`} {
			result, found := runModuleCommand(registry, session, alias+suffix)
			if !found || result != modules.Continue {
				t.Fatalf("dispatch %q: %v %v", alias+suffix, found, result)
			}
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("%d requests", calls.Load())
	}
	for _, input := range []string{"azure-get-token-suffix --help", "short ", "short --help"} {
		if _, found := runModuleCommand(registry, session, input); found {
			t.Errorf("unexpected dispatch for %q", input)
		}
	}
	for _, input := range []string{`azure-get-token --resource 'unterminated`, "36 --help", "get-azure-token --bad"} {
		if _, found := runModuleCommand(registry, session, input); !found {
			t.Errorf("Azure input not handled: %q", input)
		}
	}
	if calls.Load() != 6 {
		t.Fatal("invalid dispatch made a request")
	}
	for _, completion := range []string{setUpCompletionMainMenu().Tree(""), ui.SetUpCompletionMainMenu().Tree("")} {
		for _, alias := range []string{"azure-get-token", "get-azure-token"} {
			if !strings.Contains(completion, alias) {
				t.Errorf("completion missing %s", alias)
			}
		}
	}
}

func TestAzureMainHelper(t *testing.T) {
	if os.Getenv("PEIRATES_AZURE_MAIN_HELPER") != "1" {
		return
	}
	azureMetadataClient.Endpoint = os.Getenv("PEIRATES_AZURE_FIXTURE")
	azureMetadataClient.InstanceEndpoint = os.Getenv("PEIRATES_AZURE_FIXTURE") + "/metadata/instance"
	azureConfigPath = os.Getenv("PEIRATES_AZURE_CONFIG")
	os.Args = []string{"peirates", "-c", "-m", os.Getenv("PEIRATES_AZURE_COMMAND")}
	Main()
}

func TestAzureMainMFlag(t *testing.T) {
	var calls atomic.Int32
	var discoveries atomic.Int32
	configPath := filepath.Join(t.TempDir(), "missing-azure.json")
	requests := make(chan azure.TokenRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata/instance" {
			discoveries.Add(1)
			fmt.Fprintf(w, `{"compute":{"tagsList":[{"name":%q,"value":%q}]}}`, azure.KubeletIdentityTag, discoveredClientA)
			return
		}
		calls.Add(1)
		requests <- azure.TokenRequest{Resource: r.URL.Query().Get("resource"), ClientID: r.URL.Query().Get("client_id"), ObjectID: r.URL.Query().Get("object_id")}
		if r.Header.Get("Metadata") != "true" {
			t.Error("missing metadata header")
		}
		if strings.Contains(r.URL.Query().Get("resource"), "failure") {
			w.WriteHeader(400)
			return
		}
		writeAzureFixture(w)
	}))
	defer server.Close()
	for _, alias := range []string{"36", "azure-get-token", "get-azure-token"} {
		for _, test := range []struct {
			suffix, want      string
			request, discover bool
		}{
			{"", "Bearer token: test-bearer-secret", true, true},
			{" --resource https://vault.azure.net --object-id object", "Bearer token: test-bearer-secret", true, false},
			{" --resource api://failure", "Azure IMDS HTTP 400", true, true},
			{" --list-identities", discoveredClientA, false, true},
			{" --no-discovery", "Bearer token: test-bearer-secret", true, false},
			{" --help", "Usage: azure-get-token", false, false},
			{" --unknown", "flag provided", false, false},
		} {
			t.Run(alias+test.suffix, func(t *testing.T) {
				before := calls.Load()
				beforeDiscovery := discoveries.Load()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAzureMainHelper$")
				cmd.Env = append(os.Environ(), "PEIRATES_AZURE_MAIN_HELPER=1", "PEIRATES_AZURE_FIXTURE="+server.URL, "PEIRATES_AZURE_CONFIG="+configPath, "PEIRATES_AZURE_COMMAND="+alias+test.suffix)
				output, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(output), test.want) {
					t.Fatalf("err=%v output=%s", err, output)
				}
				if strings.Contains(string(output), "Resource URI [") {
					t.Fatal("-m prompted")
				}
				want := int32(0)
				if test.request {
					want = 1
					selection := <-requests
					expected := azure.TokenRequest{Resource: azure.DefaultResource}
					if test.discover {
						expected.ClientID = discoveredClientA
					}
					if strings.Contains(test.suffix, "vault.azure.net") {
						expected.Resource = "https://vault.azure.net"
						expected.ObjectID = "object"
					}
					if strings.Contains(test.suffix, "api://failure") {
						expected.Resource = "api://failure"
					}
					if selection != expected {
						t.Errorf("request=%+v want=%+v", selection, expected)
					}
				}
				if calls.Load()-before != want {
					t.Fatalf("requests=%d want=%d", calls.Load()-before, want)
				}
				wantDiscovery := int32(0)
				if test.discover {
					wantDiscovery = 1
				}
				if discoveries.Load()-beforeDiscovery != wantDiscovery {
					t.Fatalf("discovery requests=%d want=%d", discoveries.Load()-beforeDiscovery, wantDiscovery)
				}
			})
		}
	}
}
