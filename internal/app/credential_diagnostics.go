package app

import "strings"

// redactCredentialArgs keeps timeout and verbose diagnostics from revealing
// credentials passed to the embedded kubectl subprocess.
func redactCredentialArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	nextSecret := false
	for index, arg := range redacted {
		if nextSecret {
			redacted[index] = "<redacted>"
			nextSecret = false
			continue
		}
		name, _, equals := strings.Cut(arg, "=")
		switch name {
		case "--token", "--password", "--client-key", "--client-key-data", "-t":
			if equals {
				redacted[index] = name + "=<redacted>"
			} else {
				nextSecret = true
			}
		default:
			if strings.Contains(arg, "k8s-aws-v1.") {
				redacted[index] = "<redacted>"
			}
		}
	}
	return redacted
}
