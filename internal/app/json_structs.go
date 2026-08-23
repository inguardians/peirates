package app

import "github.com/inguardians/peirates/internal/model"

// MountInfo is used by mountRootfs
type MountInfo struct {
	yamlBuild string
	image     string
	namespace string
}

// KubeRoles are used for JSON parsing
type KubeRoles = model.KubeRoles

// PodDetails is populated by GetPodsInfo (JSON parsing from kubectl get pods)
type PodDetails = model.PodDetails

// SecretDetails unmarshalls secrets
type SecretDetails struct {
	Data []struct {
		Namespace string `json:"namespace"`
		Token     string `json:"token"`
	}
	Metadata struct {
		Name string `json:"name"`
	}
	SecretType string `json:"type"`
}

// GetNodeDetails unmarshalls node data
type GetNodeDetails struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Addresses []struct {
				Address string `json:"address"`
				Type    string `json:"type"`
			} `json:"addresses"`
		} `json:"status"`
	} `json:"items"`
}

type AWSS3BucketObject struct {
	Data string `json:"Data"`
}

type PodNamespaceContainerTuple = model.PodNamespaceContainerTuple
