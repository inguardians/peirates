package app

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func jwtSegment(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestServiceAccountHelpers(t *testing.T) {
	var accounts []ServiceAccount
	if !AddNewServiceAccount(" default ", "token", "test", &accounts) || len(accounts) != 1 {
		t.Fatal("expected account to be added")
	}
	if AddNewServiceAccount("default", "other", "test", &accounts) {
		t.Fatal("expected trimmed duplicate to be rejected")
	}
	if accounts[0].DiscoveryMethod != "test" || accounts[0].DiscoveryTime.IsZero() {
		t.Fatalf("unexpected account: %#v", accounts[0])
	}

	pair := MakeClientCertificateKeyPair("client", "cert", "key", "https://api", "ca")
	if pair.Name != "client" || pair.ClientKeyData != "key" || pair.APIServer != "https://api" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestAssignAuthenticationMethods(t *testing.T) {
	info := &ServerInfo{ClientCertData: "old", ClientKeyData: "old", ClientCertName: "old"}
	assignServiceAccountToConnection(ServiceAccount{Name: "sa", Token: "tok"}, info)
	if info.TokenName != "sa" || info.Token != "tok" || info.ClientCertData != "" || info.ClientKeyData != "" {
		t.Fatalf("unexpected token assignment: %#v", info)
	}

	assignAuthenticationCertificateAndKeyToConnection(ClientCertificateKeyPair{Name: "cert", ClientCertificateData: "cert-data", ClientKeyData: "key-data", APIServer: "https://api", CACert: "ca-data"}, info)
	t.Cleanup(func() { _ = os.Remove(info.CAPath) })
	data, err := os.ReadFile(info.CAPath)
	if err != nil || string(data) != "ca-data" {
		t.Fatalf("CA file = %q, %v", data, err)
	}
	if info.Token != "" || info.TokenName != "" || info.Namespace != "default" || info.ClientCertName != "cert" {
		t.Fatalf("unexpected certificate assignment: %#v", info)
	}
}

func TestJWTServiceAccountParsing(t *testing.T) {
	good := jwtSegment(`{"alg":"RS256"}`) + "." + jwtSegment(`{"sub":"system:serviceaccount:ns:name","n":1}`) + ".sig"
	parts, err := ParseJWT(good)
	if err != nil || parts.Header["alg"] != "RS256" || parts.Payload["n"].(float64) != 1 || parts.Signature != "sig" {
		t.Fatalf("ParseJWT() = %#v, %v", parts, err)
	}
	if _, sub, err := parseServiceAccountJWTReturnSub(good); err != nil || sub != "system:serviceaccount:ns:name" {
		t.Fatalf("sub = %q, %v", sub, err)
	}
	if decoded, err := decodeJWTBase64urlSegment("eyJ4IjoieSJ9"); err != nil || string(decoded) != `{"x":"y"}` {
		t.Fatalf("segment = %q, %v", decoded, err)
	}
	for _, token := range []string{"too.few", "%%.e30.sig", jwtSegment("not-json") + ".e30.sig"} {
		if _, err := ParseJWT(token); err == nil {
			t.Fatalf("ParseJWT(%q) unexpectedly succeeded", token)
		}
	}
	if _, _, err := parseServiceAccountJWTReturnSub(jwtSegment(`{"x":1}`) + "." + jwtSegment(`{"no_sub":true}`) + ".sig"); err == nil || !strings.Contains(err.Error(), "sub") {
		t.Fatalf("missing sub error = %v", err)
	}
}

func TestPrintJWT(t *testing.T) {
	if err := printJWT(jwtSegment(`{"a":true}`) + "." + jwtSegment(`{"b":true}`) + ".sig"); err != nil {
		t.Fatal(err)
	}
	if err := printJWT("invalid"); err == nil {
		t.Fatal("expected invalid JWT error")
	}
}
