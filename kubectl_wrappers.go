package peirates

// kubectl_wrappers.go contains a bunch of helper functions for executing
// kubectl's codebase as if it were a separate executable. However, kubectl
// IS NOT BEING EXECUTED AS A SEPARATE EXECUTABLE! See the comments on
// kubectlAuthCanI for an example of how this can cause unexpected behavior.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	kubectl "k8s.io/kubernetes/pkg/kubectl/cmd"
)

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
	cmd := exec.Cmd{
		Path:   "/proc/self/exe",
		Args:   append([]string{"kubectl"}, cmdArgs...),
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	cmd.Start()

	// runKubectl has a timeout to deal with kubectl commands running forever.
	// However, `kubectl exec` commands may take an arbitrary
	// amount of time, so we disable the timeout when `exec` is found in the args.

	// We also do the same for `kubectl delete` commands, as they can wait quite a long time.
	longRunning := false
	for _, arg := range cmdArgs {
		if arg == "exec" || arg == "delete" {
			longRunning = true
			break
		}
	}
	if !longRunning {
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
				log.Printf(
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
				cmd.Process.Kill()
				return
			}
		}()
	}

	return cmd.Wait()
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

// runKubectlWithByteSliceForStdin is runKubectlSimple but you can pass in some bytes for stdin. Conven
func runKubectlWithByteSliceForStdin(cfg ServerInfo, stdinBytes []byte, cmdArgs ...string) ([]byte, []byte, error) {
	stdin := bytes.NewReader(append(stdinBytes, '\n'))
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	err := runKubectlWithConfig(cfg, stdin, &stdout, &stderr, cmdArgs...)

	return stdout.Bytes(), stderr.Bytes(), err
}

// kubectlAuthCanI now has a history... We can't use the built in
// `kubectl auth can-i <args...>`, because when the response to the auth check
// is "no", kubectl exits with exit code 1. This has the unfortunate side
// effect of exiting peirates too, since we aren't running kubectl as a
// subprocess.
//
// The takeaway here is that we have to do it another way. See https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access
// for more details.
func kubectlAuthCanI(cfg ServerInfo, verb, resource string) bool {

	type SelfSubjectAccessReviewResourceAttributes struct {
		Group     string `json:"group,omitempty"`
		Resource  string `json:"resource"`
		Verb      string `json:"verb"`
		Namespace string `json:"namespace,omitempty"`
	}

	type SelfSubjectAccessReviewSpec struct {
		ResourceAttributes SelfSubjectAccessReviewResourceAttributes `json:"resourceAttributes"`
	}

	type SelfSubjectAccessReviewQuery struct {
		APIVersion string                      `json:"apiVersion"`
		Kind       string                      `json:"kind"`
		Spec       SelfSubjectAccessReviewSpec `json:"spec"`
	}

	type SelfSubjectAccessReviewResponse struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}

	if UseAuthCanI != true {
		return true
	}

	query := SelfSubjectAccessReviewQuery{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SelfSubjectAccessReview",
		Spec: SelfSubjectAccessReviewSpec{
			ResourceAttributes: SelfSubjectAccessReviewResourceAttributes{
				Group:     "",
				Resource:  resource,
				Verb:      verb,
				Namespace: cfg.Namespace,
			},
		},
	}

	var response SelfSubjectAccessReviewResponse

	err := DoKubernetesAPIRequest(cfg, "POST", "apis/authorization.k8s.io/v1/selfsubjectaccessreviews", query, &response)
	if err != nil {
		fmt.Printf("[-] kubectlAuthCanI failed to perform SelfSubjectAccessReview api requests with error %s: assuming you don't have permissions.\n", err.Error())
		return false
	}

	return response.Status.Allowed
}

// ExecKubectlAndExit runs the internally compiled `kubectl` code as if this was the `kubectl` binary. stdin/stdout/stderr are process streams. args are process args.
func ExecKubectlAndExit() {
	// Based on code from https://github.com/kubernetes/kubernetes/blob/2e0e1681a6ca7fe795f3bd5ec8696fb14687b9aa/cmd/kubectl/kubectl.go#L44
	cmd := kubectl.NewKubectlCommand(os.Stdin, os.Stdout, os.Stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
