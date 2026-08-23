package kube

import "github.com/inguardians/peirates/internal/model"

// ServerInfo aliases the shared Kubernetes API server connection details.
type ServerInfo = model.ServerInfo

// ServiceAccount aliases the shared Kubernetes service account credentials.
type ServiceAccount = model.ServiceAccount

// ClientCertificateKeyPair aliases the shared client certificate credentials.
type ClientCertificateKeyPair = model.ClientCertificateKeyPair

// RequestConfig describes a raw request to a Kubernetes endpoint.
type RequestConfig struct {
	Host              string
	Port              int
	Method            string
	HTTPS             bool
	IgnoreHTTPSErrors bool
}

// PodDetails aliases the shared Kubernetes pod details.
type PodDetails = model.PodDetails

// Roles aliases the shared Kubernetes role collections.
type Roles = model.KubeRoles
