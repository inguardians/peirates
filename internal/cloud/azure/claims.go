package azure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// IdentityClaims contains unverified JWT claims for display only.
type IdentityClaims struct {
	ManagedIdentityResourceID string
	ClientID                  string
	PrincipalID               string
	TenantID                  string
	SourceResourceID          string
}

// DecodeIdentityClaims inspects a JWT payload without verifying its signature.
// Missing, blank, or non-string claims are omitted. Errors contain no token data
// and must not prevent the caller from using an otherwise acquired token.
func DecodeIdentityClaims(accessToken string) (IdentityClaims, error) {
	if len(accessToken) > maxResponseBytes {
		return IdentityClaims{}, errors.New("token exceeds the 1 MiB decoding limit")
	}
	parts := strings.SplitN(accessToken, ".", 4)
	if len(parts) != 3 || parts[0] == "" {
		return IdentityClaims{}, errors.New("token is not a decodable JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return IdentityClaims{}, errors.New("token is not a decodable JWT")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return IdentityClaims{}, errors.New("token is not a decodable JWT")
	}
	claim := func(name string) string {
		var value string
		if err := json.Unmarshal(fields[name], &value); err != nil || strings.TrimSpace(value) == "" {
			return ""
		}
		return value
	}
	clientID := claim("appid")
	if azp := claim("azp"); azp != "" && (claim("ver") == "2.0" || clientID == "") {
		clientID = azp
	}
	return IdentityClaims{
		ManagedIdentityResourceID: claim("xms_mirid"),
		ClientID:                  clientID,
		PrincipalID:               claim("oid"),
		TenantID:                  claim("tid"),
		SourceResourceID:          claim("xms_az_rid"),
	}, nil
}
