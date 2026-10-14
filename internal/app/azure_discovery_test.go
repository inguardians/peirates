package app

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inguardians/peirates/internal/cloud/azure"
)

const (
	discoveredClientA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	discoveredClientB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func TestAzureDiscoveredIdentitySelection(t *testing.T) {
	config := fmt.Sprintf(`{"useManagedIdentityExtension":true,"userAssignedIdentityID":%q,"aadClientSecret":"config-secret"}`, discoveredClientA)
	for _, test := range []struct {
		name, config, tag, input, wantID, wantOutput string
		args                                         []string
		interactive, request, skipDiscovery          bool
		status                                       int
	}{
		{name: "interactive config", config: config, input: "\n\n", interactive: true, request: true, wantID: discoveredClientA, wantOutput: "userAssignedIdentityID"},
		{name: "interactive tag", tag: discoveredClientB, input: "\n\n", interactive: true, request: true, wantID: discoveredClientB, wantOutput: azure.KubeletIdentityTag},
		{name: "interactive choice", config: config, tag: discoveredClientB, input: "\n2\n", interactive: true, request: true, wantID: discoveredClientB, wantOutput: "(required)"},
		{name: "interactive default override", config: config, input: "\ndefault\n", interactive: true, request: true, wantOutput: "Identity selection: default"},
		{name: "interactive manual override", config: config, input: "\nclient-id\nmanual-client\n", interactive: true, request: true, wantID: "manual-client", wantOutput: "Identity client-id:"},
		{name: "interactive multiple blank", config: config, tag: discoveredClientB, input: "\n\n", interactive: true, wantOutput: "explicit choice"},
		{name: "interactive invalid number", config: config, input: "\n2\n", interactive: true, wantOutput: "listed number"},
		{name: "interactive cancellation", config: config, input: "\n", interactive: true, wantOutput: "cancelled"},
		{name: "noninteractive deduplicated", config: config, tag: strings.ToUpper(discoveredClientA), request: true, wantID: discoveredClientA, wantOutput: "Using discovered client ID"},
		{name: "noninteractive tag", tag: discoveredClientB, request: true, wantID: discoveredClientB, wantOutput: "Using discovered client ID"},
		{name: "noninteractive ambiguity", config: config, tag: discoveredClientB, wantOutput: "select one with --client-id"},
		{name: "inline options skip prompts", config: config, args: []string{"--resource", "https://vault.azure.net"}, interactive: true, request: true, wantID: discoveredClientA, wantOutput: "https://vault.azure.net"},
		{name: "explicit identity skips discovery", config: `malformed config-secret`, tag: discoveredClientB, args: []string{"--client-id", "explicit-client"}, request: true, skipDiscovery: true, wantID: "explicit-client", wantOutput: "Bearer token:"},
		{name: "no discovery uses default", config: config, tag: discoveredClientB, args: []string{"--no-discovery"}, request: true, skipDiscovery: true, wantOutput: "Identity selection: default"},
		{name: "no candidates uses default", request: true, wantOutput: "identities may still be assigned"},
		{name: "tag failure retains config", config: config, status: 403, request: true, wantID: discoveredClientA, wantOutput: "IMDS instance tags: HTTP 403"},
		{name: "config failure retains tag", config: `{"useManagedIdentityExtension":"config-secret"}`, tag: discoveredClientB, request: true, wantID: discoveredClientB, wantOutput: "malformed Azure config"},
		{name: "listing only", config: config, tag: discoveredClientB, args: []string{"--list-identities"}, interactive: true, wantOutput: discoveredClientB},
		{name: "empty listing", args: []string{"--list-identities"}, wantOutput: "No Azure client IDs discovered"},
		{name: "help skips discovery", config: config, tag: discoveredClientB, args: []string{"--help"}, skipDiscovery: true, wantOutput: "Usage:"},
		{name: "conflicting flags skip discovery", config: config, args: []string{"--list-identities", "--client-id", "explicit"}, skipDiscovery: true, wantOutput: "cannot be combined"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var discoveries, tokens atomic.Int32
			useAzureDiscoveryFixture(t, test.config, func(w http.ResponseWriter, r *http.Request) {
				discoveries.Add(1)
				if r.Header.Get("Metadata") != "true" || r.URL.RawQuery != "api-version=2021-02-01" {
					t.Errorf("unexpected discovery request: %s %v", r.URL, r.Header)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
					fmt.Fprint(w, `{"error_description":"metadata-secret"}`)
					return
				}
				fmt.Fprintf(w, `{"compute":{"tagsList":[{"name":%q,"value":%q},{"name":"unrelated","value":"metadata-secret"}]}}`, azure.KubeletIdentityTag, test.tag)
			}, func(w http.ResponseWriter, r *http.Request) {
				tokens.Add(1)
				if r.URL.Query().Get("client_id") != test.wantID || r.URL.Query().Get("object_id") != "" || r.URL.Query().Get("msi_res_id") != "" {
					t.Errorf("unexpected token selector: %v", r.URL.Query())
				}
				resource := azure.DefaultResource
				if strings.Contains(test.name, "inline options") {
					resource = "https://vault.azure.net"
				}
				if r.URL.Query().Get("resource") != resource {
					t.Errorf("unexpected resource: %v", r.URL.Query())
				}
				writeAzureFixture(w)
			})
			session := NewSession(ServerInfo{})
			session.Interactive = test.interactive
			priorKey := AzureTokenKey{"client_id", "prior", azure.DefaultResource}
			prior := AzureSessionToken{Token: azure.Token{AccessToken: "retained-secret", ExpiresOn: time.Now().Add(time.Hour)}}
			session.AzureTokens = map[AzureTokenKey]AzureSessionToken{priorKey: prior}
			var out bytes.Buffer
			input := strings.NewReader(test.input)
			requestAzureToken(session, test.args, input, &out)
			if !strings.Contains(out.String(), test.wantOutput) {
				t.Fatalf("output missing %q: %s", test.wantOutput, &out)
			}
			wantDiscoveries, wantTokens, wantEntries := int32(1), int32(0), 1
			if test.skipDiscovery {
				wantDiscoveries = 0
			}
			if test.request {
				wantTokens, wantEntries = 1, 2
			}
			if discoveries.Load() != wantDiscoveries || tokens.Load() != wantTokens || len(session.AzureTokens) != wantEntries || session.AzureTokens[priorKey] != prior {
				t.Fatalf("discovery=%d tokens=%d entries=%d output=%s", discoveries.Load(), tokens.Load(), len(session.AzureTokens), &out)
			}
			if test.request {
				for key, entry := range session.AzureTokens {
					if key != priorKey && entry.Selection.ClientID != test.wantID {
						t.Fatalf("discovered selector not retained: %+v", entry.Selection)
					}
				}
			}
			for _, secret := range []string{"config-secret", "metadata-secret", "retained-secret"} {
				if strings.Contains(out.String(), secret) {
					t.Fatalf("discovery exposed %s", secret)
				}
			}
			if len(test.args) > 0 && (strings.Contains(out.String(), "Resource URI [") || strings.Contains(out.String(), "Identity [")) {
				t.Fatal("options unexpectedly prompted")
			}
		})
	}
}

func TestAzureDiscoveryPromptPreservesNextCommand(t *testing.T) {
	useAzureDiscoveryFixture(t, "", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"compute":{"tagsList":[{"name":%q,"value":%q}]}}`, azure.KubeletIdentityTag, discoveredClientA)
	}, func(w http.ResponseWriter, _ *http.Request) { writeAzureFixture(w) })
	input := strings.NewReader("\n1\nnext-menu-command\n")
	requestAzureToken(NewSession(ServerInfo{}), nil, input, io.Discard)
	remaining, err := io.ReadAll(input)
	if err != nil || string(remaining) != "next-menu-command\n" {
		t.Fatalf("remaining=%q err=%v", remaining, err)
	}
}
