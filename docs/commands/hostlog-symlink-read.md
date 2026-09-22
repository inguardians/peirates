# Host-log symlink file read

## Menu entry

- **Menu item:** `33`
- **Canonical command:** `hostlog-symlink-read`
- **Alias:** `hostlog-read`
- **Maturity:** Experimental on Linux; temporarily creates one node-visible symlink

## Purpose

Read one operator-selected file from a Kubernetes node when the current
container already has the node's `/var/log` directory, or a descendant such as
`/var/log/pods`, mounted read-write. Peirates creates a temporary symlink below
that mounted directory and asks the kubelet `/logs/` file server to follow it
through the authenticated API-server `nodes/proxy` route.

The result is a bounded single-file read. It does not provide a shell, create a
Pod, replace an active CRI log, search the node recursively, or prove access to
the physical machine beneath a virtualized or containerized Kubernetes node.

## Prerequisites and authorization

The Peirates process must run on Linux and have all of the following:

- an existing direct mount whose mountinfo root is `/var/log` or a normalized
  descendant, or a direct mount placed exactly at container path `/var/log`;
- effective write and search access to that mount;
- a mount that is read-write according to `/proc/self/mountinfo`;
- the name of the Kubernetes node running the current container;
- an API-server connection using a bearer token or client certificate; and
- a kubelet with the system-log `/logs/` handler enabled behind the API-server
  node proxy.

When authorization prechecks are enabled, the active principal must pass a
SelfSubjectAccessReview for `get` on the cluster-scoped `nodes/proxy`
subresource. This permission is powerful: it grants access to kubelet APIs
through the API server and can expose more than system logs. Peirates also
probes the actual `/logs/` route before creating a symlink because an allowed
review does not prove that the kubelet handler is enabled.

TLS verification uses the configured CA data or CA file. Certificate
verification is disabled only when the operator explicitly selected Peirates'
existing insecure-TLS option.

## Usage

Select the command from the full interactive menu with any supported form:

```text
33
hostlog-symlink-read
hostlog-read
```

Peirates reads three complete lines:

```text
Mounted host-log path [auto-detect]: /mnt/node-logs
Kubernetes node name [worker-a]: worker-a
Absolute host target path: /etc/hostname
```

Press Enter at the first prompt to auto-detect the mount. Auto-detection
proceeds only when exactly one writable and accessible candidate qualifies;
multiple candidates require an explicit normalized absolute mount point.
Kubernetes runtime staging can obscure the original bind source with `/` or a
runtime-specific path. Peirates accepts that fallback only when the container
destination is exactly `/var/log`, and reports that its hostPath origin remains
unproven. Arbitrary destinations do not qualify through this fallback.

When `NODE_NAME` is present, it is offered as the second prompt's default.
Peirates does not infer a node name from the container hostname. With no
`NODE_NAME`, the node prompt is required. The third prompt always requires one
normalized absolute target path other than `/`; there is no sensitive default.

Direct module invocation uses the same prompts:

```sh
printf '\n\n/etc/hostname\n' | peirates -c -m hostlog-symlink-read
```

The example accepts unique mount auto-detection and the `NODE_NAME` default.

## What it does

Peirates validates all prompt input, then performs a subresource-aware access
review when authorization checking is enabled. It sends a bounded `HEAD`
request to `/api/v1/nodes/<node>/proxy/logs/`. If an intermediary rejects
`HEAD` with method-not-allowed, Peirates falls back to a one-byte bounded `GET`
and discards the directory response. Authorization denial, an absent handler,
TLS failure, timeout, and an oversized response remain distinct errors.

Only after that preflight succeeds does the Linux action repeat mount
qualification, open the selected directory without following it, and create a
cryptographically named `.peirates-hostlog-*` symlink. The link points directly
to the selected target. Peirates requests the link below kubelet `/logs/`,
using the correct path prefix when the mounted node directory is below
`/var/log`.

The file response is limited to 1 MiB and the request to 10 seconds. Error
bodies are sanitized and limited to 4 KiB. Redirects are refused. Peirates
does not print bearer tokens, client keys, certificates, authorization
headers, probe listings, or file data in diagnostics.

Before returning any file bytes, Peirates verifies that the temporary entry is
still the exact symlink it created, removes it, and verifies successful cleanup
through the action result. It then writes the returned bytes without changing
or appending to them. Treat all successful output as sensitive.

## Expected output

A successful read reports the selected inputs, successful API proxy preflight,
the qualified mount and node-log root, the exact temporary link removed, and
the node boundary reached. The final output is:

```text
Host file content follows (treat as sensitive):
<exact bounded file bytes>
```

No diagnostic is printed after those bytes. If cleanup fails, Peirates clears
the result and withholds all returned file content.

## Side effects and cleanup

The command creates one temporary symbolic link inside the selected node log
mount. It never writes to the selected target. Normal return, HTTP failure,
timeout, context cancellation, and handled `SIGINT` or `SIGTERM` all run guarded
cleanup.

Cleanup verifies both the no-follow filesystem identity and target of the link
before unlinking it. Peirates refuses a replacement or retargeting observed
during that verification, reports the full temporary path, and withholds file
content. Linux has no atomic compare-and-unlink operation: a write-capable peer
that replaces the randomized name after verification but before `unlinkat`
could cause the replacement to be removed. A detected replacement instead
leaves the entry for manual inspection. `SIGKILL`, process crashes, node loss,
and filesystem failure also cannot guarantee cleanup; inspect the path reported
in the error after such an event.

## Failure modes and limitations

- Non-Linux execution reports the action as unsupported.
- A missing, read-only, inaccessible, symlinked, ambiguous, or changed mount
  fails closed before mutation.
- A nonstandard container destination qualifies only when mountinfo retains a
  root at `/var/log` or one of its normalized descendants.
- Relative, unnormalized, empty, and root target paths are rejected.
- Missing `nodes/proxy` authorization stops before symlink creation when the
  authorization check is enabled.
- An enabled authorization check can still be followed by a denied proxy
  request because cluster policy can change between requests.
- A disabled kubelet system-log handler normally returns not-found through the
  proxy.
- AppArmor, SELinux, seccomp, user namespaces, or another policy can deny
  symlink creation or kubelet traversal despite the local prerequisite scan.
- Files larger than 1 MiB are rejected rather than truncated.
- The kubelet route reaches the Kubernetes node serving the request; it does
  not establish that the node is the underlying physical host.

## Implementation and tests

- [Host-log action](../../internal/modules/hostlog)
- [Bounded Kubernetes transport](../../internal/kube/raw.go)
- [Application prompts and proxy adapter](../../internal/app/container_escape_modules.go)
- [Application registration](../../internal/app/module_registry.go)
- [Unit tests](../../internal/app/container_escape_modules_test.go)
- [Disposable Kind integration test](../../test/hostlog-read-kind-integration.sh)
