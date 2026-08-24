//go:build kubelet_integration

package app

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAnonymousKubeletPodListingAndExec(t *testing.T) {
	nodeIP := requiredIntegrationEnv(t, "PEIRATES_KUBELET_NODE_IP")
	namespace := requiredIntegrationEnv(t, "PEIRATES_KUBELET_NAMESPACE")
	podName := requiredIntegrationEnv(t, "PEIRATES_KUBELET_POD")
	containerName := requiredIntegrationEnv(t, "PEIRATES_KUBELET_CONTAINER")

	podsURL := "http://" + nodeIP + ":10255/pods"
	podDetails, err := getKubeletPods(podsURL)
	if err != nil {
		t.Fatalf("anonymous kubelet pod listing at %s: %v", podsURL, err)
	}

	found := false
	for _, container := range runningPodContainers(podDetails) {
		if container.PodNamespace == namespace && container.PodName == podName && container.ContainerName == containerName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("anonymous kubelet listing did not contain running container %s/%s/%s", namespace, podName, containerName)
	}

	// Pod listing uses the read-only kubelet port above; execution must use the
	// HTTPS kubelet endpoint on port 10250.
	runURL := fmt.Sprintf("https://%s:10250/run/%s/%s/%s/", nodeIP, namespace, podName, containerName)
	output, err := executeKubeletCommand(runURL, "id")
	if err != nil {
		t.Fatalf("anonymous kubelet id exec through port 10250 at %s: %v", runURL, err)
	}
	if !strings.Contains(output, "uid=") {
		t.Fatalf("anonymous kubelet id exec output = %q, want output containing uid=", output)
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s must be set by test/kubelet-kind-integration.sh", name)
	}
	return value
}
