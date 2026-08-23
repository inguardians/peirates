// Package model contains data shared by Peirates capability packages.
package model

import "time"

// ServiceAccount stores one discovered service-account credential.
type ServiceAccount struct {
	Name            string
	Token           string
	DiscoveryTime   time.Time
	DiscoveryMethod string
}

// ClientCertificateKeyPair stores certificate and key data for one principal.
type ClientCertificateKeyPair struct {
	Name                  string
	ClientKeyData         string
	ClientCertificateData string
	APIServer             string
	CACert                string
}
