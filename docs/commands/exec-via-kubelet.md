# Extract pod tokens through kubelet APIs

## Menu entry

- Number: `22`
- Canonical command: `exec-via-kubelet`
- Alias: `exec-via-kubelets`

## Purpose

Enumerate running containers through each node's kubelet and ask the kubelet to read the mounted service-account token from every discovered container. Every HTTP 200 response body is printed and offered to the current Peirates session as a token; the implementation does not validate that it is a JWT.

This is a cluster-wide credential-access technique. Use it only during an explicitly authorized assessment that permits kubelet probing, command execution in workloads, and collection of service-account credentials.

## Prerequisites and authorization

The current Kubernetes identity needs cluster-scoped access to get/list node information; the implementation checks `get nodes` and then runs `get nodes -o json`. Network access from Peirates to node ports `10255` and `10250` is required.

The kubelets must expose unauthenticated pod listing over HTTP on port `10255` and accept an unauthenticated HTTPS POST to `/run/...` on port `10250`, or otherwise accept these requests without credentials. Peirates does not attach its Kubernetes bearer token, kubelet client certificates, or other credentials to either request. Modern, securely configured kubelets normally do not meet these conditions.

## Usage

Interactive menu:

```text
22
```

The canonical command and alias can be entered instead. The module asks no questions.

One-shot module mode:

```text
peirates -c -m exec-via-kubelet
```

`22` and `exec-via-kubelets` are accepted after `-m` as well. This path is non-interactive; `-c` is optional and only skips cloud detection.

## What it does

1. Retrieves all nodes as JSON from the API server.
2. For every non-`Hostname` node address, requests `http://<address>:10255/pods` without authentication.
3. Selects running container statuses, excluding a container literally named `pause`.
4. Sends an unauthenticated HTTPS POST to `https://<address>:10250/run/<namespace>/<pod>/<container>/` with `cmd=cat` and `cmd=/var/run/secrets/kubernetes.io/serviceaccount/token` query values.
5. Prints the returned body and adds it to Peirates' in-memory service-account list without JWT validation. The storage key contains the namespace and pod name but not the container name, so only the first result from a multi-container pod is retained; later results are printed and rejected as duplicate names.

TLS certificate verification is deliberately disabled for the kubelet exec request.

## Expected output

For each node address, Peirates prints the pod-listing URL. For each running container it prints the kubelet run URL, then either an error or `Got service account token for ns:<namespace> pod:<pod> container:<container>:` followed by the token.

Successful output contains live credentials. Treat terminal scrollback and captured logs as sensitive assessment data.

## Side effects and cleanup

The hard-coded command reads a token file and is not intended to modify the container or cluster. Retrieved tokens are retained in the current Peirates session and may be used through the service-account menu. They are lost when the process exits unless exported separately.

No Kubernetes resources are created. Securely delete any authorized logs or exports containing tokens according to the assessment's data-handling plan, and remediate anonymous kubelet access after testing.

## Failure modes

- The node authorization check is known in source comments not to detect every cluster-scope denial correctly; the subsequent node request can still fail.
- Port `10255` may be disabled, firewalled, or require authentication.
- Port `10250` usually requires authentication and authorization; Peirates sends neither.
- The implementation ignores kubelet TLS identity, exposing requests and returned tokens to interception on an untrusted network.
- It tries every non-hostname address. Multiple addresses can duplicate work, while failure on an earlier address skips the rest of that node.
- There is no explicit HTTP timeout, so an unresponsive node can stall the module.
- Containers without the standard token mount return an error; automount may be disabled or the path may differ.
- The kubelet `/run` endpoint or anonymous authorization behavior may not exist on the target version.
- `getKubeletPods` ignores the HTTP status code from port `10255`; a non-2xx body that happens to decode as the expected JSON shape may be treated as a pod listing.
- Every HTTP 200 body from `/run` is printed and passed to storage without token validation, so an error page or other unexpected content returned with status 200 can be mislabeled as a service-account token.

## Implementation and tests

- [Menu registration and handler](../../internal/app/module_registry.go)
- [Aliases](../../internal/app/dispatch.go)
- [Kubelet enumeration and exec implementation](../../internal/app/exec_via_kubelet_api.go)
- [Unit tests](../../internal/app/exec_via_kubelet_api_test.go)
- [Guarded live integration test](../../internal/app/exec_via_kubelet_api_integration_test.go)
- [Disposable Kind test harness](../../test/kubelet-kind-integration.sh)
- [Integration-test notes](../../test/README.md)

Unit tests cover container filtering, command argument encoding, and HTTPS run-endpoint errors. The guarded integration test exercises the unauthenticated listing and run helpers by deliberately enabling anonymous kubelet access only in a disposable Kind cluster; it does not drive the complete `exec-via-kubelet` module.
