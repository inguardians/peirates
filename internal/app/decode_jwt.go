package app

import (
	"encoding/base64"
	"fmt"

	"github.com/inguardians/peirates/internal/token"
)

// JWT aliases the token package JSON Web Token representation.
type JWT = token.JWT

func decodeJWT(value string) JWT { return token.Decode(value) }

func decodeBase64(value string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		panic(fmt.Sprintf("Error decoding base64url: %s", err.Error()))
	}
	return string(decoded)
}
