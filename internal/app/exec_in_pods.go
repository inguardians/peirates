package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func execInPodMenu(connectionString ServerInfo, interactive bool) {
	reader := bufio.NewReader(os.Stdin)

	println(`
	[1] Run command on a specific pod
	[2] Run command on all pods
	`)
	fmt.Printf("\nPeirates (execInPods):># ")

	input, err := readExecMenuLine(reader)
	if err != nil {
		fmt.Printf("Problem with reading input: %v\n", err)
		pauseToHitEnter(interactive)
		return
	}
	println("[+] Please provide the command to run in the pods: ")

	commandToRunInPods, err := readExecMenuLine(reader)
	if err != nil {
		fmt.Printf("Problem with reading command: %v\n", err)
		pauseToHitEnter(interactive)
		return
	}

	if commandToRunInPods == "" {
		fmt.Print("[-] ERROR - command string was empty.")
		pauseToHitEnter(interactive)
		return
	}

	switch input {
	case "1":

		println("[+] Enter the pod name in which to run the command: ")

		podToRunIn, err := readExecMenuLine(reader)
		if err != nil {
			fmt.Printf("Problem with reading pod name: %v\n", err)
			pauseToHitEnter(interactive)
			return
		}
		podsToRunTheCommandIn := []string{podToRunIn}

		if len(podsToRunTheCommandIn) > 0 {
			execInListPods(connectionString, podsToRunTheCommandIn, commandToRunInPods)
		} else {
			println("[-] No pods found to run the command in.")
			return
		}

	case "2":

		execInAllPods(connectionString, commandToRunInPods)
	}
}

func readExecMenuLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// execInAllPods() runs a command in all running pods
func execInAllPods(connectionString ServerInfo, command string) {
	runningPods := getPodList(connectionString)
	execInListPods(connectionString, runningPods, command)
}

// execInListPods() runs a command in all pods in the provided list
func execInListPods(connectionString ServerInfo, pods []string, command string) {
	if !kubectlAuthCanI(connectionString, "exec", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to exec commands in pods")
		return
	}

	println("[+] Running supplied command in list of pods")
	for _, execPod := range pods {
		execInPodOut, _, err := runKubectlSimple(connectionString, "exec", "-it", execPod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Printf("[-] Executing %s in Pod %s failed: %s\n", command, execPod, err)
		} else {
			println(" ")
			println(string(execInPodOut))
		}
	}
}
