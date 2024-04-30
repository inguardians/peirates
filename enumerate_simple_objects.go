package peirates

import (
	"encoding/json"
	"fmt"
)

// GetPodsInfo gets details for all pods in json output and stores in PodDetails struct
func GetPodsInfo(connectionString ServerInfo, podDetails *PodDetails) {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to get pods")
		return
	}

	println("[+] Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		println("[-] Unable to retrieve details from this pod: ", err)
	} else {
		println("[+] Retrieving details for all pods was successful: ")
		err := json.Unmarshal(podDetailOut, &podDetails)
		if err != nil {
			println("[-] Error unmarshaling data: ", err)
		}
	}
}

// PrintHostMountPoints prints all pods' host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func PrintHostMountPoints(podInfo PodDetails) {
	println("[+] Getting all host mount points for pods in current namespace")
	for _, item := range podInfo.Items {
		// println("+ Host Mount Points for Pod: " + item.Metadata.Name)
		for _, volume := range item.Spec.Volumes {
			if volume.HostPath.Path != "" {
				println("\tHost Mount Point: " + string(volume.HostPath.Path) + " found for pod " + item.Metadata.Name)
			}
		}
	}
}

// PrintHostMountPointsForPod prints a single pod's host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func PrintHostMountPointsForPod(podInfo PodDetails, pod string) {
	println("[+] Getting all Host Mount Points only for pod: " + pod)
	for _, item := range podInfo.Items {
		if item.Metadata.Name == pod {
			for _, volume := range item.Spec.Volumes {
				if volume.HostPath.Path != "" {
					println("\tHost Mount Point: " + string(volume.HostPath.Path))
				}
			}
		}
	}
}

// GetRoles enumerates all roles in use on the cluster (in the default namespace).
// It parses all roles into a KubeRoles object.
func GetRoles(connectionString ServerInfo, kubeRoles *KubeRoles) {
	println("[+] Getting all Roles")
	rolesOut, _, err := runKubectlSimple(connectionString, "get", "role", "-o", "json")
	if err != nil {
		println("[-] Unable to retrieve roles from this pod: ", err)
	} else {
		println("[+] Retrieving roles was successful: ")
		err := json.Unmarshal(rolesOut, &kubeRoles)
		if err != nil {
			println("[-] Error unmarshaling data: ", err)
		}

	}
}

// GetNodesInfo runs kubectl get nodes -o json.
func GetNodesInfo(connectionString ServerInfo) {
	println("[+] Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "nodes", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		println("[-] Unable to retrieve node details: ", err)
	}
}

// getPodList returns an array of running pod information, parsed from "kubectl -n namespace get pods -o json"
func getPodList(connectionString ServerInfo) []string {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to get pods")
		return []string{}
	}

	responseJSON, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "json")
	if err != nil {
		fmt.Printf("[-] Error while getting pods: %s\n", err.Error())
		return []string{}
	}

	type PodsResponse struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	var response PodsResponse
	err = json.Unmarshal(responseJSON, &response)
	if err != nil {
		fmt.Printf("[-] Error while getting pods: %s\n", err.Error())
		return []string{}
	}

	pods := make([]string, len(response.Items))

	for i, pod := range response.Items {
		pods[i] = pod.Metadata.Name
	}

	return pods
}

// Get the names of the available Secrets from the current namespace and a list of service account tokens
func getSecretList(connectionString ServerInfo) ([]string, []string) {

	if !kubectlAuthCanI(connectionString, "get", "secrets") {
		println("[-] Permission Denied: your service account isn't allowed to list secrets")
		return []string{}, []string{}
	}

	type SecretsResponse struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Type string `json:"type"`
		} `json:"items"`
	}

	secretsJSON, _, err := runKubectlSimple(connectionString, "get", "secrets", "-o", "json")
	if err != nil {
		fmt.Printf("[-] Error while getting secrets: %s\n", err.Error())
		return []string{}, []string{}
	}

	var response SecretsResponse
	err = json.Unmarshal(secretsJSON, &response)
	if err != nil {
		fmt.Printf("[-] Error while getting secrets: %s\n", err.Error())
		return []string{}, []string{}
	}

	secrets := make([]string, len(response.Items))
	var serviceAccountTokens []string

	for i, secret := range response.Items {
		secrets[i] = secret.Metadata.Name
		if secret.Type == "kubernetes.io/service-account-token" {
			serviceAccountTokens = append(serviceAccountTokens, secret.Metadata.Name)
		}
	}

	return secrets, serviceAccountTokens
}

func printListOfPods(connectionString ServerInfo) {
	runningPods := getPodList(connectionString)
	for _, listpod := range runningPods {
		println("[+] Pod Name: " + listpod)
	}

}

func findVolumeMounts(connectionString ServerInfo, podInfo *PodDetails) {
	println("[1] Get all host mount points [all]")
	println("[2] Get volume mount points for a specific pod [single]")
	println("\nPeirates:># ")
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		println("Problem with scanln: %v", err)
		return
	}

	GetPodsInfo(connectionString, podInfo)

	switch input {
	case "1", "all":
		println("[+] Getting volume mounts for all pods")
		// BUG: Need to make it so this Get doesn't print all info even though it gathers all info.
		PrintHostMountPoints(*podInfo)

		//MountRootFS(allPods, connectionString)
	case "2", "single":
		println("[+] Please provide the pod name: ")
		var userResponse string
		_, err = fmt.Scanln(&userResponse)
		fmt.Printf("[+] Printing volume mount points for %s\n", userResponse)
		PrintHostMountPointsForPod(*podInfo, userResponse)
	}
}
