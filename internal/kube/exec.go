package kube

import "fmt"

// ExecInPods runs command through /bin/sh in each named pod.
func (c *Client) ExecInPods(cfg ServerInfo, pods []string, command string) {
	if !c.AuthCanI(cfg, "exec", "pods") {
		println("[-] Permission Denied: your service account isn't allowed to exec commands in pods")
		return
	}
	for _, pod := range pods {
		output, _, err := c.Run(cfg, "exec", "-it", pod, "--", "/bin/sh", "-c", command)
		if err != nil {
			fmt.Printf("[-] Executing %s in Pod %s failed: %s\n", command, pod, err)
			continue
		}
		println(string(output))
	}
}

// ExecInAllPods discovers pods and runs command in each one.
func (c *Client) ExecInAllPods(cfg ServerInfo, command string) {
	c.ExecInPods(cfg, c.PodList(cfg), command)
}
