package kube

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// ServiceAccountPath is the standard projected service-account directory.
const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

// AddServiceAccount adds account when no existing trimmed name matches.
func AddServiceAccount(name, token, discoveryMethod string, accounts *[]ServiceAccount) bool {
	for _, account := range *accounts {
		if strings.TrimSpace(account.Name) == strings.TrimSpace(name) {
			return false
		}
	}
	*accounts = append(*accounts, ServiceAccount{Name: name, Token: token, DiscoveryTime: time.Now(), DiscoveryMethod: discoveryMethod})
	return true
}

// NewClientCertificateKeyPair builds a certificate credential.
func NewClientCertificateKeyPair(name, certificate, key, apiServer, ca string) ClientCertificateKeyPair {
	return ClientCertificateKeyPair{Name: name, ClientCertificateData: certificate, ClientKeyData: key, APIServer: apiServer, CACert: ca}
}

// AssignServiceAccount switches cfg to token authentication.
func AssignServiceAccount(account ServiceAccount, cfg *ServerInfo) {
	cfg.TokenName, cfg.Token = account.Name, account.Token
	cfg.ClientCertData, cfg.ClientKeyData, cfg.ClientCertName = "", "", ""
}

// AssignClientCertificate switches cfg to certificate authentication.
func AssignClientCertificate(pair ClientCertificateKeyPair, cfg *ServerInfo) error {
	file, err := os.CreateTemp("/tmp", "*-ca.crt")
	if err != nil {
		return err
	}
	if _, err = file.WriteString(pair.CACert); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	cfg.CAPath = file.Name()
	cfg.ClientCertData, cfg.ClientKeyData, cfg.ClientCertName = pair.ClientCertificateData, pair.ClientKeyData, pair.Name
	cfg.APIServer, cfg.Namespace = pair.APIServer, "default"
	cfg.TokenName, cfg.Token = "", ""
	return nil
}

// ParseServiceAccountSubject extracts the sub claim from a JWT.
func ParseServiceAccountSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token: expected three parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	subject, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("'sub' field not found or not a string")
	}
	return subject, nil
}

// ImportPodServiceAccount reads the standard in-pod connection context.
func ImportPodServiceAccount() ServerInfo {
	cfg := ServerInfo{APIServer: "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT")}
	if token, err := os.ReadFile(ServiceAccountPath + "token"); err == nil {
		cfg.Token = string(token)
		if subject, err := ParseServiceAccountSubject(cfg.Token); err == nil && strings.HasPrefix(subject, "system:serviceaccount:") {
			cfg.TokenName = strings.TrimPrefix(subject, "system:serviceaccount:")
		} else {
			cfg.TokenName = "Pod ns:" + cfg.Namespace + ":" + os.Getenv("HOSTNAME")
		}
	}
	if namespace, err := os.ReadFile(ServiceAccountPath + "namespace"); err == nil {
		cfg.Namespace = string(namespace)
	}
	if certificate, err := os.ReadFile(ServiceAccountPath + "ca.crt"); err == nil {
		cfg.CAPath, cfg.CACertData = ServiceAccountPath+"ca.crt", string(certificate)
	}
	return cfg
}
