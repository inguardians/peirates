package azure

import (
	"encoding/base64"
	"strings"
	"testing"
)

func identityClaimsFixture(payload string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2lnbmF0dXJl"
}

func TestDecodeIdentityClaims(t *testing.T) {
	const identity = "/subscriptions/test/resourceGroups/test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agentpool"
	const source = "/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/virtualMachineScaleSets/nodes/virtualMachines/3"
	for _, test := range []struct {
		name, payload string
		want          IdentityClaims
	}{
		{
			name:    "user assigned v1",
			payload: `{"ver":"1.0","xms_mirid":"` + identity + `","appid":"client","oid":"principal","tid":"tenant","xms_az_rid":"` + source + `","aud":"https://management.azure.com/","unrelated":"ignored"}`,
			want:    IdentityClaims{ManagedIdentityResourceID: identity, ClientID: "client", PrincipalID: "principal", TenantID: "tenant", SourceResourceID: source},
		},
		{
			name:    "system assigned without source claim",
			payload: `{"xms_mirid":"` + source + `","appid":"client","oid":"principal","tid":"tenant"}`,
			want:    IdentityClaims{ManagedIdentityResourceID: source, ClientID: "client", PrincipalID: "principal", TenantID: "tenant"},
		},
		{
			name:    "v2 client ID",
			payload: `{"ver":"2.0","azp":"v2-client","oid":"principal","tid":"tenant"}`,
			want:    IdentityClaims{ClientID: "v2-client", PrincipalID: "principal", TenantID: "tenant"},
		},
		{
			name:    "v2 prefers azp",
			payload: `{"ver":"2.0","azp":"v2-client","appid":"v1-client"}`,
			want:    IdentityClaims{ClientID: "v2-client"},
		},
		{
			name:    "v1 prefers appid",
			payload: `{"ver":"1.0","azp":"v2-client","appid":"v1-client"}`,
			want:    IdentityClaims{ClientID: "v1-client"},
		},
		{
			name:    "azp without version",
			payload: `{"azp":"client"}`,
			want:    IdentityClaims{ClientID: "client"},
		},
		{
			name:    "invalid fields preserve available claims",
			payload: `{"xms_mirid":[],"appid":123,"azp":"client","oid":null,"tid":"tenant","xms_az_rid":{}}`,
			want:    IdentityClaims{ClientID: "client", TenantID: "tenant"},
		},
		{
			name:    "blank and missing fields",
			payload: `{"xms_mirid":" \n","appid":"","oid":false,"aud":"https://management.azure.com/"}`,
		},
		{
			name:    "claim names are case sensitive",
			payload: `{"OID":"wrong-case","TID":"wrong-case","APPID":"wrong-case"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeIdentityClaims(identityClaimsFixture(test.payload))
			if err != nil || got != test.want {
				t.Fatalf("claims=%+v err=%v want=%+v", got, err, test.want)
			}
		})
	}
}

func TestDecodeIdentityClaimsInvalidTokens(t *testing.T) {
	for _, test := range []struct{ name, token string }{
		{"empty", ""},
		{"opaque", "opaque-bearer-secret"},
		{"extra segments", "header.payload.signature.extra"},
		{"empty header", ".e30.signature"},
		{"invalid base64url", "header.%%%.signature"},
		{"invalid JSON", identityClaimsFixture(`{"oid":"payload-secret",`)},
		{"trailing JSON", identityClaimsFixture(`{"oid":"payload-secret"}{}`)},
		{"JSON array", identityClaimsFixture(`["payload-secret"]`)},
		{"JSON string", identityClaimsFixture(`"payload-secret"`)},
		{"JSON null", identityClaimsFixture(`null`)},
		{"oversized", strings.Repeat("s", maxResponseBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeIdentityClaims(test.token)
			if err == nil || got != (IdentityClaims{}) {
				t.Fatalf("claims=%+v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "secret") || len(err.Error()) > 100 {
				t.Fatal("decoding error exposed token data")
			}
		})
	}
}
