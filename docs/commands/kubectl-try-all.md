# Run kubectl with every context

## Menu entry

- **Menu item:** Unnumbered
- **Canonical command:** `kubectl-try-all`
- **Maturity:** Supported

## Purpose

Run one kubectl operation with every collected service-account and client-certificate context and show the results for every successful identity.

## Prerequisites and authorization

Peirates must have discovered or imported authorization contexts. Each identity needs the permissions required by the requested kubectl operation.

## Usage

```text
kubectl-try-all get pods
```

```sh
peirates -m 'kubectl-try-all get pods'
```

The kubectl arguments must be present on the same line.

## What it does

Peirates temporarily selects each service account, then each client certificate, and invokes embedded kubectl. It displays successful results, counts successful principals, and restores the original authentication context after all attempts.

## Expected output

Each context name is announced. Output from successful attempts is printed, followed by the number of principals that succeeded. If none succeed, Peirates reports an error.

## Side effects and cleanup

Every authorized identity runs the requested operation. A mutating command can therefore perform the same change several times or under several audit identities. Peirates restores its local context but does not undo remote changes.

## Failure modes

No collected contexts, expired credentials, RBAC denial, API connectivity errors, and kubectl failures can leave the success count at zero. Arguments use whitespace splitting rather than shell parsing.

## Implementation and tests

See [`peirates.go`](../../internal/app/peirates.go) and [`kubectl_wrappers.go`](../../internal/app/kubectl_wrappers.go). Behavior is covered by [`module_commands_test.go`](../../internal/app/module_commands_test.go) and [`kubectl-try-all-kind-integration.sh`](../../test/kubectl-try-all-kind-integration.sh).
