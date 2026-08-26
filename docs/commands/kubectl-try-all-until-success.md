# Try kubectl contexts until one succeeds

## Menu entry

- **Menu item:** Unnumbered
- **Canonical command:** `kubectl-try-all-until-success`
- **Maturity:** Supported

## Purpose

Run one kubectl operation across collected authorization contexts, stopping when the first service account or client certificate succeeds.

## Prerequisites and authorization

Peirates must have discovered or imported at least one context. Each attempted identity is subject to Kubernetes authentication and authorization for the requested operation.

## Usage

```text
kubectl-try-all-until-success get secrets
```

```sh
peirates -m 'kubectl-try-all-until-success get secrets'
```

The command requires kubectl arguments on the same line.

## What it does

Peirates tries service accounts first and client certificates second. It temporarily assigns each context, runs the embedded kubectl command, restores the original context, and returns after the first zero exit status.

## Expected output

The command prints each identity name as it is tried and prints the first successful kubectl result. If no principal succeeds, it reports that the action could not be performed.

## Side effects and cleanup

The selected kubectl operation may mutate the cluster or execute code, and earlier failed attempts may still have partial server-side effects. Peirates restores its original authentication context, but it does not undo Kubernetes operations.

## Failure modes

An empty context collection, invalid credentials, RBAC denial, connectivity failures, or a nonzero kubectl exit for every identity produces failure. Success is determined by process exit status, not by interpreting output.

## Implementation and tests

See [`peirates.go`](../../internal/app/peirates.go) and [`kubectl_wrappers.go`](../../internal/app/kubectl_wrappers.go). Behavior is covered by [`module_commands_test.go`](../../internal/app/module_commands_test.go), with live multi-context coverage in [`kubectl-try-all-kind-integration.sh`](../../test/kubectl-try-all-kind-integration.sh).
