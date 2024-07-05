package peirates

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWT structure to hold decoded JWT parts
type JWT struct {
	Header       string
	Payload      string
	Signature    string
	RawHeader    string
	RawPayload   string
	RawSignature string
}

// decodeJWT decodes a JWT token into its parts
func decodeJWT(token string) JWT {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		panic("Invalid JWT format")
	}

	header := decodeBase64(parts[0])
	payload := decodeBase64(parts[1])
	signature := parts[2]

	jwt := JWT{
		Header:       header,
		Payload:      payload,
		Signature:    signature,
		RawHeader:    parts[0],
		RawPayload:   parts[1],
		RawSignature: parts[2],
	}

	return jwt
}

// decodeBase64 decodes a base64url-encoded string
func decodeBase64(str string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("Error decoding base64url: %s", err.Error()))
	}
	return string(decoded)
}

// PrettyPrintPayload pretty prints the decoded JWT payload
func (jwt *JWT) PrettyPrintPayload() string {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(jwt.Payload), "", "  ")
	if err != nil {
		return "Error pretty printing JSON"
	}
	return string(prettyJSON.Bytes())
}
