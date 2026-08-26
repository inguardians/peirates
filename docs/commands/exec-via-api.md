# Execute commands in pods through the API server

## Menu entry

- Number: `21`
- Canonical command: `exec-via-api`
- Aliases: none

## Purpose

Run an operator-supplied shell command in one named pod or in every pod returned from the current namespace through the Kubernetes API server.

Only use this command against pods covered by an explicit authorization. The supplied command runs with the target container's identity and can change application data, credentials, processes, or availability.

## Prerequisites and authorization

The current connection must reach the API server. Pod exec normally requires `create` on the `pods/exec` subresource. The current implementation first performs a compatibility SelfSubjectAccessReview for the legacy `exec` verb on `pods`; that check must report allowed unless authorization prechecks are disabled.

The all-pods branch additionally needs `get` and `list` on `pods`: Peirates checks `get`, then performs a collection listing. Target pods must be running and their selected/default containers must include `/bin/sh`.

## Usage

Interactive menu:

1. Enter `21` or `exec-via-api`.
2. Choose `1` for one pod or `2` for all pods.
3. Enter the command. For choice `1`, then enter the pod name.

One-shot module mode invokes the same prompt-driven submenu. For example, to run `id` in one pod:

```sh
printf '1\nid\n%s\n' '<pod-name>' | peirates -c -m exec-via-api
```

`peirates -c -m 21` is equivalent. This is not fully non-interactive: the selection, command, and optional pod name are read as newline-delimited standard input. The `-c` flag only skips cloud detection.

## What it does

For a specific pod, Peirates uses the name entered by the operator. For all pods, it gets every pod name in the current namespace; despite the source comment saying "running pods," the list is not filtered by phase.

For each name, Peirates runs the equivalent of:

```text
kubectl exec -it <pod> -- /bin/sh -c <command>
```

No container is selected explicitly, so kubectl's default-container behavior applies. Pods are processed sequentially and one failure does not stop later attempts.

## Expected output

Peirates prints `Running supplied command in list of pods`, followed by each successful command's standard output. A failed target produces `Executing <command> in Pod <pod> failed` and the returned error.

The command does not provide an aggregate success count or a failing process status in one-shot module mode; inspect each target's output.

## Side effects and cleanup

Peirates creates no Kubernetes objects. Side effects are entirely determined by the supplied command and may affect one pod or every pod in the namespace. Plan a command-specific rollback before execution and verify each target individually afterward.

Because the all-pods branch can include the Peirates pod itself and non-running pods, do not assume that all attempted targets completed or that repeated execution is safe.

## Failure modes

- The legacy authorization precheck may deny execution even when `create pods/exec` is allowed.
- The all-pods branch fails or produces an empty target set without pod `get` permission.
- Pending, completed, terminating, or otherwise non-running pods are still attempted.
- A multi-container pod may select an unintended default container.
- Containers without `/bin/sh` cannot run the command.
- The `-it` flags can cause TTY-related behavior in some automation contexts.
- An empty command is rejected. An empty pod name in choice `1` is still passed to kubectl and fails there. A submenu choice other than `1` or `2` exits silently without executing anything.
- Command errors affect only the current pod; later pods are still attempted, and the module does not return a nonzero status for partial failure.

## Implementation and tests

- [Menu registration and handler](../../internal/app/module_registry.go)
- [Numeric dispatch](../../internal/app/dispatch.go)
- [Pod-exec implementation](../../internal/app/exec_in_pods.go)
- [Pod enumeration](../../internal/app/enumerate_simple_objects.go)
- [Disposable Kind integration test](../../test/exec-via-api-kind-integration.sh)
- [Integration-test notes](../../test/README.md)

The live integration test covers numeric selection of one pod and canonical selection of all pods using harmless marker files in a disposable cluster.
