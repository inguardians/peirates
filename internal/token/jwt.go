// Package token provides helpers for inspecting authentication tokens.
package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWT contains the decoded and encoded parts of a JSON Web Token.
type JWT struct {
	Header, Payload, Signature          string
	RawHeader, RawPayload, RawSignature string
}

// Decode splits and decodes a JWT. Invalid input intentionally panics.
func Decode(value string) JWT {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		panic("Invalid JWT format")
	}
	return JWT{Header: decodeBase64(parts[0]), Payload: decodeBase64(parts[1]), Signature: parts[2], RawHeader: parts[0], RawPayload: parts[1], RawSignature: parts[2]}
}

func decodeBase64(value string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		panic(fmt.Sprintf("Error decoding base64url: %s", err.Error()))
	}
	return string(decoded)
}

// PrettyPrintPayload formats the decoded JSON payload for display.
func (jwt *JWT) PrettyPrintPayload() string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(jwt.Payload), "", "  "); err != nil {
		return "Error pretty printing JSON"
	}
	return prettyJSON.String()
}
