# Direct kubelet nodes/proxy execution

## Menu entry

- **Menu item:** `34`
- **Canonical command:** `nodes-proxy-exec`
- **Aliases:** None
- **Maturity:** Experimental; executes one bounded command in one explicitly selected container

## Purpose

Demonstrate the command-execution authority associated with Kubernetes `get`
permission on the `nodes/proxy` subresource. The command reviews every service-
account token already stored in the current Peirates session, lets the operator
select one token whose node-specific review succeeded, and uses that token to
contact one kubelet directly over HTTPS. It then executes one non-interactive
command through a WebSocket HTTP `GET` request.

This behavior is not a CVE. Kubernetes documents that `get nodes/proxy` is not
read-only and can reach kubelet APIs capable of command execution.

## Prerequisites and authorization

The command requires:

- the exact Kubernetes node name;
- at least one service-account token already stored in Peirates;
- node-specific `get nodes/proxy` permission for a stored token;
- direct network access from Peirates to that node's kubelet HTTPS origin,
  normally on port 10250;
- a kubelet that accepts the selected bearer token and supports remote-command
  WebSockets; and
- kubelet-specific CA data or a CA file that validates the serving certificate,
  unless the operator explicitly accepts insecure TLS.

Each stored token is checked against the current API-server origin and trust
settings. Peirates does not discover or try other clusters for those tokens.
A positive access review does not prove that the kubelet is reachable or that
the same token can authenticate to it.

For each token, `allowed` means its node-specific `get nodes/proxy` review
succeeded, `denied` means the API server rejected that permission, `error`
means the review could not be completed, and `unchecked` means authorization
review was explicitly disabled. For GET-qualified tokens, Peirates also checks
`create nodes/proxy` as a negative control. Token values, token prefixes, JWT
payloads, and token digests are never displayed.

## Usage

Select item `34` from the full menu or invoke the canonical module directly:

```sh
peirates -m nodes-proxy-exec
```

Direct invocation remains interactive. The command asks for a node name,
reviews all stored tokens, requires an explicit allowed-token index, then asks
for a direct kubelet HTTPS origin, kubelet TLS settings, a numbered running-
container target, and command argv as a JSON string array. The default argv is
`["id"]`; Peirates does not implicitly add `/bin/sh -c`.

The kubelet TLS mode defaults to `insecure`. Pressing Enter at that prompt does
not immediately disable verification: Peirates prints a warning and still
requires the exact `INSECURE-KUBELET-TLS` acknowledgement. Select `ca-data` or
`ca-file` explicitly to verify the kubelet serving certificate.

Immediately before execution, the operator must type:

```text
EXEC-VIA-NODES-PROXY-<node-name>
```

EOF or any other response cancels without opening the execution WebSocket.

## What it does

Peirates takes a value snapshot of every stored service-account entry when the
module starts. It reviews all entries with at most four concurrent requests and
prints results in their original order, continuing after individual denials or
errors and after the first allowed token. Duplicate credential values may share
one in-memory review, but each stored entry remains separately selectable.

Selecting a token creates a private connection copy; the active Peirates
identity and the stored-token list are not changed. Peirates contacts the
explicit kubelet origin directly rather than using the API-server
`nodes/<name>/proxy` route. It retrieves a bounded `/pods` response, presents
only currently running regular, init, and ephemeral containers on the selected
node, and requires an explicit target choice.

After a fresh target revalidation and exact confirmation, Peirates opens one
HTTP `GET` WebSocket to `/exec/<namespace>/<pod>/<container>`. It requests
remote-command protocols v5 through v1 in preference order. There is no POST,
SPDY, API-server-proxy, or insecure-TLS fallback.

## Expected output

Before confirmation, the command reports the selected node, aggregate and
per-token access-review states, selected credential label and original index,
kubelet origin and TLS mode, running-container count, target, and JSON argv.
Sensitive credential values are omitted.

After execution, Peirates reports the negotiated protocol, exit status,
separate bounded stdout and stderr, and one classification:

- `confirmed-get-only-exec`: GET allowed, CREATE denied, and execution succeeded;
- `broad-proxy-access`: GET and CREATE allowed and execution succeeded;
- `execution-confirmed-authz-unchecked`: reviews were disabled and execution succeeded;
- `permission-candidate`: GET was allowed but execution was not proved; or
- `not-exploitable-from-here`: authorization, authentication, reachability,
  target validation, or execution failed.

Successful container execution does not by itself prove control of the node or
of a physical host beneath a virtualized or containerized node.

## Side effects and cleanup

**Warning:** the confirmed action starts one process inside another container.
Direct kubelet execution bypasses API-server admission and might not appear as
a pod-exec event in Kubernetes API-server audit logs.

The first release is limited to one node, one running container, and one
non-interactive command per invocation. It does not forward stdin, allocate a
TTY, create workloads, harvest credentials, install persistence, launch a
reverse shell automatically, or execute across multiple targets. No cluster
objects require cleanup, but the selected command can itself have side effects;
review the exact argv before confirming.

Read-only requests time out after 10 seconds. Command execution times out after
30 seconds. The pod-list response is limited to 8 MiB, error details to 4 KiB,
and combined stdout plus stderr to 1 MiB. Reaching the output limit cancels the
execution rather than silently truncating it.

## Failure modes

- No stored tokens stops before any kubelet request.
- An invalid node, token index, HTTPS origin, TLS setting, target, or JSON argv
  fails closed.
- A denied, errored, or missing credential cannot be selected. An unchecked
  credential requires a second warning and explicit acknowledgement.
- Network policy, firewalls, kubelet authentication or authorization, serving-
  certificate differences, and unsupported WebSocket negotiation can prevent
  execution after an allowed API-server access review.
- A container can stop or move between enumeration and final revalidation.
- Empty argv, NUL bytes, too many arguments, or oversized argv are rejected.
- A non-zero remote exit status is reported separately; a structured completed
  status can still prove that kubelet executed the requested process.

Defenders should remove `nodes/proxy` permissions where possible, use fine-
grained kubelet permissions for read-only needs, and restrict direct network
access to kubelet port 10250.

## Implementation and tests

- [Application prompts and rendering](../../internal/app/nodes_proxy_exec.go)
- [Capability orchestration](../../internal/modules/nodesproxyexec)
- [Direct kubelet transport](../../internal/kube/kubelet_websocket.go)
- [Application tests](../../internal/app/nodes_proxy_exec_test.go)
- [Disposable Kind integration test](../../test/nodes-proxy-exec-kind-integration.sh)
