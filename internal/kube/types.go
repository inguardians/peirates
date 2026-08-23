package kube

import "github.com/inguardians/peirates/internal/model"

type ServerInfo = model.ServerInfo

type ServiceAccount = model.ServiceAccount

type ClientCertificateKeyPair = model.ClientCertificateKeyPair

// RequestConfig describes a raw request to a Kubernetes endpoint.
type RequestConfig struct {
	Host              string
	Port              int
	Method            string
	HTTPS             bool
	IgnoreHTTPSErrors bool
}

type PodDetails = model.PodDetails

type KubeRoles = model.KubeRoles
