# Namespace menu

## Menu entry

- Number: `2`
- Canonical command: `ns-menu`
- Aliases: `namespace-menu`, `ns`, `namespace`
- Maturity: Stable; list and switch have live Kind coverage.

## Purpose

List active Kubernetes namespaces or change the namespace used by subsequent Peirates Kubernetes operations.

## Prerequisites and authorization

Peirates needs a configured Kubernetes API server, trusted CA (or `-k`), and usable token or client certificate. Listing namespaces is cluster-scoped and normally requires `list` on `namespaces`. With authorization prechecks enabled, Peirates first submits a SelfSubjectAccessReview for `get` on `namespaces`.

## Usage

At the main interactive prompt, enter `2`, `ns-menu`, or an alias. Then choose:

```text
1 / list      list active namespaces
2 / switch    choose the current namespace
```

Module mode is supported, but it still requires submenu input (and a namespace for `switch`):

```sh
peirates -m ns-menu
```

The submenu and switch prompt use separate readline instances, so piped automation may need to pace the two responses.

`list-ns` and `switch-ns` invoke the two actions directly; they are related commands rather than aliases for `ns-menu`.

## What it does

The list action runs the equivalent of `kubectl get namespaces`, parses the table output, and prints rows whose status is `Active`. The switch action retrieves the same list for display and completion, then updates the current connection's namespace if the entered name is present. If the list could not be retrieved, Peirates permits a manually entered namespace.

The submenu performs one action before returning or exiting module mode.

## Expected output

List prints one active namespace per line. Switch prints the known active namespaces and prompts for the target. It has no explicit success message; a valid selection is reflected by the current namespace in later Peirates banners and Kubernetes requests.

## Side effects and cleanup

Switch changes only the in-memory `Namespace` field for the current Peirates process. It does not create, delete, or modify Kubernetes namespaces. Switch back through this menu, or restart Peirates, to restore the prior selection.

When client-certificate authentication is active, the shared kubectl wrapper writes the client certificate and private key to temporary `/tmp/peirates-*` files for the list request and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

## Failure modes

- A failed permission precheck or `kubectl get namespaces` call produces an error and an empty list.
- Only rows shown as `Active` in kubectl's human-readable table are retained.
- A name absent from a successfully retrieved non-empty list is rejected.
- If retrieval fails or yields no names, any non-empty manually entered name is accepted without verifying that it exists.
- The precheck asks about `get`, while the actual collection request normally needs `list`; RBAC may therefore pass the check and still fail the operation.
- Client-certificate contexts bypass the authorization precheck.

## Implementation and tests

- [Submenu implementation](../../internal/app/menu_namespaces.go)
- [Namespace listing and switching](../../internal/app/config.go)
- [Authorization check and kubectl wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/config_output_node_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/namespace-kind-integration.sh)
