package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner is the kubectl execution seam used by tests and callers.
type CommandRunner func(stdin io.Reader, stdout, stderr io.Writer, args ...string) error

// Client groups Kubernetes operations with replaceable transport seams.
type Client struct {
	RunCommand CommandRunner
	APIRequest func(ServerInfo, string, string, any, any) error
	Output     func(string)
	Verbose    bool
}

// NewClient returns a client using Peirates' embedded-kubectl subprocess path.
func NewClient() *Client {
	return &Client{RunCommand: runCommand, APIRequest: DoAPIRequest, Output: func(output string) { print(output) }}
}

func runCommand(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Cmd{Path: "/proc/self/exe", Args: append([]string{"kubectl"}, args...), Stdin: stdin, Stdout: stdout, Stderr: stdout}
	if err := cmd.Start(); err != nil {
		return err
	}
	longRunning := false
	for _, arg := range args {
		if arg == "exec" || arg == "delete" {
			longRunning = true
			break
		}
	}
	if !longRunning {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
				log.Printf("\nKubectl took too long! This usually happens because the remote IP is wrong.\n")
				_ = cmd.Process.Kill()
			}
		}()
	}
	return cmd.Wait()
}

// RunWithConfig executes kubectl with connection and authentication arguments.
func (c *Client) RunWithConfig(cfg ServerInfo, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if cfg.APIServer == "" {
		return errors.New("api server not set")
	}
	connectionArgs := []string{"--server=" + cfg.APIServer}
	if !cfg.IgnoreTLS {
		if cfg.CAPath == "" {
			return errors.New("certificate authority path not defined - will not communicate with api server")
		}
		connectionArgs = append(connectionArgs, "--certificate-authority="+cfg.CAPath)
	} else {
		connectionArgs = append(connectionArgs, "--insecure-skip-tls-verify=true")
	}
	appendNamespace := true
	for _, arg := range args {
		if arg == "--all-namespaces" || arg == "-n" {
			appendNamespace = false
		}
	}
	if appendNamespace {
		connectionArgs = append(connectionArgs, "-n", cfg.Namespace)
	}
	if cfg.Token != "" {
		connectionArgs = append(connectionArgs, "--token="+cfg.Token)
	}
	var temporaryFiles []*os.File
	defer func() {
		for _, file := range temporaryFiles {
			_ = file.Close()
		}
	}()
	if cfg.ClientCertData != "" {
		certificate, err := os.CreateTemp("/tmp", "peirates-")
		if err != nil {
			return errors.New("could not create a temp file for the client cert requested")
		}
		temporaryFiles = append(temporaryFiles, certificate)
		if _, err = io.WriteString(certificate, cfg.ClientCertData); err != nil {
			return errors.New("could not write to temp file for the client cert requested")
		}
		if err = certificate.Sync(); err != nil {
			return err
		}
		key, err := os.CreateTemp("/tmp", "peirates-")
		if err != nil {
			return errors.New("could not create a temp file for the client key requested")
		}
		temporaryFiles = append(temporaryFiles, key)
		if _, err = io.WriteString(key, cfg.ClientKeyData); err != nil {
			return errors.New("could not write to temp file for the client key requested")
		}
		if err = key.Sync(); err != nil {
			return err
		}
		connectionArgs = append(connectionArgs, "--client-certificate="+certificate.Name(), "--client-key="+key.Name())
	}
	runner := c.RunCommand
	if runner == nil {
		runner = runCommand
	}
	return runner(stdin, stdout, stderr, append(connectionArgs, args...)...)
}

// Run executes kubectl non-interactively and captures its output streams.
func (c *Client) Run(cfg ServerInfo, args ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	err := c.RunWithConfig(cfg, strings.NewReader(""), &stdout, &stderr, args...)
	return stdout.Bytes(), stderr.Bytes(), err
}

// AuthCanI performs a SelfSubjectAccessReview when that check is enabled.
func (c *Client) AuthCanI(cfg ServerInfo, verb, resource string) bool {
	if !cfg.UseAuthCanI || cfg.ClientCertData != "" {
		return true
	}
	query := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			ResourceAttributes struct {
				Group     string `json:"group,omitempty"`
				Resource  string `json:"resource"`
				Verb      string `json:"verb"`
				Namespace string `json:"namespace,omitempty"`
			} `json:"resourceAttributes"`
		} `json:"spec"`
	}{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
	query.Spec.ResourceAttributes.Resource = resource
	query.Spec.ResourceAttributes.Verb = verb
	query.Spec.ResourceAttributes.Namespace = cfg.Namespace
	var response struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	request := c.APIRequest
	if request == nil {
		request = DoAPIRequest
	}
	if err := request(cfg, "POST", "apis/authorization.k8s.io/v1/selfsubjectaccessreviews", query, &response); err != nil {
		fmt.Printf("[-] kubectlAuthCanI failed to perform SelfSubjectAccessReview api requests with error %s: assuming you don't have permissions.\n", err)
		return false
	}
	return response.Status.Allowed
}

// AttemptEveryAccount runs args with each discovered principal and restores cfg.
func (c *Client) AttemptEveryAccount(stopOnFirstSuccess bool, cfg *ServerInfo, accounts []ServiceAccount, certificates []ClientCertificateKeyPair, args ...string) ([]byte, []byte, error) {
	backup := *cfg
	defer func() { *cfg = backup }()
	successes := 0
	for _, account := range accounts {
		AssignServiceAccount(account, cfg)
		stdout, stderr, err := c.Run(*cfg, args...)
		if err == nil {
			successes++
			if c.Output != nil {
				c.Output(string(stdout))
			}
			if stopOnFirstSuccess {
				return stdout, stderr, nil
			}
		}
	}
	for _, certificate := range certificates {
		if err := AssignClientCertificate(certificate, cfg); err != nil {
			continue
		}
		stdout, stderr, err := c.Run(*cfg, args...)
		if err == nil {
			successes++
			if c.Output != nil {
				c.Output(string(stdout))
			}
			if stopOnFirstSuccess {
				return stdout, stderr, nil
			}
		}
	}
	if successes == 0 {
		return nil, nil, errors.New("no principals worked")
	}
	return nil, nil, nil
}
