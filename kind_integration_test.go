//go:build integration

package peirates

import (
	"os"
	"testing"
)

func TestKindListsNamespaces(t *testing.T) {
	apiServer := os.Getenv("PEIRATES_KIND_API_SERVER")
	token := os.Getenv("PEIRATES_KIND_TOKEN")
	if apiServer == "" || token == "" {
		t.Fatal("PEIRATES_KIND_API_SERVER and PEIRATES_KIND_TOKEN must be set")
	}

	var response struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	cfg := ServerInfo{APIServer: apiServer, Token: token, ignoreTLS: true}
	if err := DoKubernetesAPIRequest(cfg, "GET", "/api/v1/namespaces", nil, &response); err != nil {
		t.Fatalf("list namespaces through Peirates API client: %v", err)
	}
	for _, item := range response.Items {
		if item.Metadata.Name == "kube-system" {
			return
		}
	}
	t.Fatalf("kube-system absent from namespace response: %#v", response.Items)
}
