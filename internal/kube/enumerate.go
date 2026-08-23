package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GetPodsInfo retrieves pod details for the active namespace.
func (c *Client) GetPodsInfo(cfg ServerInfo, details *PodDetails) {
	if !c.AuthCanI(cfg, "get", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to get pods")
		return
	}
	output, _, err := c.Run(cfg, "get", "pods", "-o", "json")
	if err != nil {
		println("[-] Unable to retrieve details from this pod: ", err.Error())
		return
	}
	if err := json.Unmarshal(output, details); err != nil {
		println("[-] Error unmarshaling data: ", err.Error())
	}
}

// PodList returns pod names in the active namespace.
func (c *Client) PodList(cfg ServerInfo) []string {
	if !c.AuthCanI(cfg, "get", "pods") {
		return []string{}
	}
	output, _, err := c.Run(cfg, "get", "pods", "-o", "json")
	if err != nil {
		return []string{}
	}
	var response struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return []string{}
	}
	pods := make([]string, len(response.Items))
	for index, pod := range response.Items {
		pods[index] = pod.Metadata.Name
	}
	return pods
}

// SecretList returns all secret names and the service-account-token subset.
func (c *Client) SecretList(cfg ServerInfo) ([]string, []string) {
	if !c.AuthCanI(cfg, "get", "secrets") {
		return []string{}, []string{}
	}
	output, _, err := c.Run(cfg, "get", "secrets", "-o", "json")
	if err != nil {
		return []string{}, []string{}
	}
	var response struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Type string `json:"type"`
		} `json:"items"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return []string{}, []string{}
	}
	secrets := make([]string, len(response.Items))
	var tokens []string
	for index, secret := range response.Items {
		secrets[index] = secret.Metadata.Name
		if secret.Type == "kubernetes.io/service-account-token" {
			tokens = append(tokens, secret.Metadata.Name)
		}
	}
	return secrets, tokens
}

// GetRoles retrieves roles in the active namespace.
func (c *Client) GetRoles(cfg ServerInfo, roles *KubeRoles) {
	output, _, err := c.Run(cfg, "get", "role", "-o", "json")
	if err == nil {
		_ = json.Unmarshal(output, roles)
	}
}

// GetNodesInfo retrieves and prints node details, preserving the old command behavior.
func (c *Client) GetNodesInfo(cfg ServerInfo) {
	output, _, err := c.Run(cfg, "get", "nodes", "-o", "json")
	println(string(output))
	if err != nil {
		println("[-] Unable to retrieve node details: ", err.Error())
	}
}

// Namespaces returns active namespace names from kubectl's table output.
func (c *Client) Namespaces(cfg ServerInfo) ([]string, error) {
	if !c.AuthCanI(cfg, "get", "namespaces") {
		return []string{}, errors.New("[-] Permission Denied: your service account isn't allowed to get namespaces")
	}
	output, _, err := c.Run(cfg, "get", "namespaces")
	if err != nil {
		return []string{}, err
	}
	var namespaces []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] != "NAME" && fields[1] == "Active" {
			namespaces = append(namespaces, fields[0])
		}
	}
	return namespaces, nil
}

// PrintHostMountPoints prints hostPath volumes for all parsed pods.
func PrintHostMountPoints(details PodDetails) {
	for _, pod := range details.Items {
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath.Path != "" {
				fmt.Printf("\tHost Mount Point: %s found for pod %s\n", volume.HostPath.Path, pod.Metadata.Name)
			}
		}
	}
}

// PrintHostMountPointsForPod prints hostPath volumes for the named pod.
func PrintHostMountPointsForPod(details PodDetails, name string) {
	for _, pod := range details.Items {
		if pod.Metadata.Name != name {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath.Path != "" {
				fmt.Printf("\tHost Mount Point: %s\n", volume.HostPath.Path)
			}
		}
	}
}
