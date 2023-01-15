package peirates

import (
	"strings"
	"time"
)

// When run from a node, we gather non-token secrets.
//
// If we allow the user to gather secrets from container breakouts, we will
// need to track metadata of some sort to distinguish the path to read the data
// or simply store the entire contents.

type SecretFromPodViaNodeFS struct {
	secretName      string
	secretPath      string
	podName         string    // Pod the secret was found in, if its name can be discovered.
	DiscoveryTime   time.Time // Time the secret was found on the node's filesystem.
	DiscoveryMethod string
}

// AddNewSecretFromPodViaNodeFS adds a new service account to the existing slice, but only if the the new one is unique
// Return whether one was added - if it wasn't, it's a duplicate.
func AddNewSecretFromPodViaNodeFS(secretName, secretPath, podName string, secretsFromPodsViaNodeFS *[]SecretFromPodViaNodeFS) bool {

	// Confirm we don't have this secret already.
	// If this were likely to be large, we could use a map keyed on secretName, but this seems an unlikely problem.
	for _, secret := range *secretsFromPodsViaNodeFS {
		if strings.TrimSpace(secret.secretName) == strings.TrimSpace(secretName) {
			return false
		}
	}

	*secretsFromPodsViaNodeFS = append(*secretsFromPodsViaNodeFS,
		SecretFromPodViaNodeFS{
			secretName:      secretName,
			secretPath:      secretPath,
			podName:         podName,
			DiscoveryTime:   time.Now(),
			DiscoveryMethod: "gathered from node filesystem",
		})

	return true
}

//
//certificateSecrets *[]CertSecret, nonTokenNonCertSecrets *[]nonTokenNonCertSecrets,
//
