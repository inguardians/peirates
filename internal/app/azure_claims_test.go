package app

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inguardians/peirates/internal/cloud/azure"
)

func TestAzureRequestIdentitySummary(t *testing.T) {
	const identity = "/subscriptions/test/resourceGroups/test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agentpool"
	const source = "/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/virtualMachineScaleSets/nodes/virtualMachines/3"
	for _, test := range []struct {
		name, payload, opaque string
		want, absent          []string
		identityName          string
	}{
		{
			name:    "user assigned identity",
			payload: `{"xms_mirid":"` + identity + `","appid":"claims-client","oid":"claims-principal","tid":"claims-tenant","xms_az_rid":"` + source + `","unrelated":"do-not-display-this-claim"}`,
			want: []string{
				"Decoded identity claims (signature not verified):\n",
				"  Managed identity: " + identity + "\n",
				"  Client ID:        claims-client\n",
				"  Principal ID:     claims-principal\n",
				"  Tenant ID:        claims-tenant\n",
				"  Source resource:  " + source + "\n",
			},
			absent:       []string{"do-not-display-this-claim"},
			identityName: "agentpool",
		},
		{
			name:         "system assigned identity",
			payload:      `{"xms_mirid":"` + source + `","appid":"claims-client"}`,
			want:         []string{"  Managed identity: " + source + "\n", "  Client ID:        claims-client\n"},
			absent:       []string{"  Source resource:", "  Principal ID:", "  Tenant ID:"},
			identityName: "3",
		},
		{
			name:         "identity resource with trailing slash",
			payload:      `{"xms_mirid":"` + identity + `/"}`,
			want:         []string{"  Managed identity: " + identity + "/\n"},
			identityName: "agentpool",
		},
		{
			name:    "v2 partial identity",
			payload: `{"ver":"2.0","azp":"v2-client","oid":123,"tid":"claims-tenant"}`,
			want:    []string{"  Client ID:        v2-client\n", "  Tenant ID:        claims-tenant\n"},
			absent:  []string{"  Managed identity:", "  Principal ID:", "  Source resource:"},
		},
		{
			name:    "missing claims",
			payload: `{"aud":"https://management.azure.com/"}`,
			want:    []string{"Decoded identity claims: no supported identity fields present.\n"},
			absent:  []string{"  Managed identity:", "  Client ID:", "signature not verified"},
		},
		{
			name:   "opaque token",
			opaque: "opaque-bearer-secret",
			want:   []string{"Decoded identity claims: unavailable (token is not a decodable JWT).\n"},
		},
		{
			name:   "invalid base64url",
			opaque: "header.%%%.signature",
			want:   []string{"Decoded identity claims: unavailable (token is not a decodable JWT).\n"},
		},
		{
			name:    "invalid JSON",
			payload: `{"oid":"do-not-display-this-claim",`,
			want:    []string{"Decoded identity claims: unavailable (token is not a decodable JWT).\n"},
			absent:  []string{"do-not-display-this-claim"},
		},
		{
			name:         "escaped terminal control characters",
			payload:      `{"xms_mirid":"` + identity + `\nforged line\u001b[31m"}`,
			want:         []string{"  Managed identity: " + identity + "\\nforged line\\x1b[31m\n"},
			absent:       []string{"\nforged line", "\x1b"},
			identityName: "agentpool\nforged line\x1b[31m",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			accessToken := test.opaque
			if accessToken == "" {
				accessToken = "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(test.payload)) + ".c2lnbmF0dXJl"
			}
			var calls atomic.Int32
			useAzureFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_on":%d,"client_id":"response-client"}`, accessToken, time.Now().Add(time.Hour).Unix())
			})
			session := NewSession(ServerInfo{})
			var out bytes.Buffer
			requestAzureToken(session, []string{"--no-discovery"}, strings.NewReader(""), &out)
			output := out.String()
			for _, want := range append(test.want, "[+] Azure managed identity token\n", "Bearer token: "+accessToken+"\n") {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q: %s", want, output)
				}
			}
			for _, absent := range append(test.absent, "[-] Azure token:") {
				if strings.Contains(output, absent) {
					t.Errorf("output contains %q: %s", absent, output)
				}
			}
			if strings.Index(output, "Decoded identity claims") > strings.Index(output, "Bearer token:") {
				t.Error("identity summary should precede the bearer token")
			}
			entry := session.AzureTokens[AzureTokenKey{"client_id", "response-client", azure.DefaultResource}]
			if calls.Load() != 1 || len(session.AzureTokens) != 1 || entry.Token.AccessToken != accessToken {
				t.Fatalf("token acquisition or retention changed: requests=%d entries=%d", calls.Load(), len(session.AzureTokens))
			}
			var status bytes.Buffer
			printAzureTokenStatus(&status, session, time.Now())
			identityLabel := `client_id "response-client"`
			if test.identityName != "" {
				identityLabel = fmt.Sprintf("managed identity %q (%s)", test.identityName, identityLabel)
			}
			if !strings.Contains(status.String(), "[+] Azure token (available): "+identityLabel+"; resource ") {
				t.Errorf("menu header missing identity %q: %s", identityLabel, &status)
			}
			if strings.Contains(status.String(), "\nforged line") || strings.Contains(status.String(), "\x1b") {
				t.Fatal("menu header exposed terminal control characters")
			}
			if strings.Contains(status.String(), accessToken) {
				t.Fatal("session status exposed the bearer token")
			}
		})
	}
}
