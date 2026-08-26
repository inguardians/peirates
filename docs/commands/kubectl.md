# Run kubectl with the current context

## Menu entry

- **Menu item:** 90 (also accepted as `0`)
- **Canonical command:** `kubectl`
- **Maturity:** Supported

## Purpose

Run a kubectl subcommand through Peirates using the currently selected service-account token or client certificate, API server, namespace, and TLS settings. Peirates embeds kubectl; an external kubectl binary is not required.

## Prerequisites and authorization

The current context needs an API server and either a usable CA path or insecure TLS mode. The selected identity must be authorized for the requested Kubernetes operation.

## Usage

Enter arguments directly at the Peirates prompt:

```text
kubectl get pods
kubectl get pod api -o yaml
```

For one-shot execution, quote the complete module input:

```sh
peirates -m 'kubectl get pods'
```

Entering bare `kubectl` starts a wizard that asks for the subcommand. Bare `peirates -m kubectl` therefore still needs terminal input.

## What it does

Peirates appends connection, namespace, TLS, and authentication arguments to the embedded kubectl command. An explicit `--all-namespaces` or `-n` suppresses the current namespace. Most commands are terminated after about ten seconds; commands containing `exec` or `delete` are exempt from that timeout.

## Expected output

kubectl output is printed. If output logging is enabled, output routed through Peirates' output helper is appended to the selected file.

## Side effects and cleanup

The effects are those of the supplied kubectl command. Read commands are normally non-mutating; create, patch, delete, exec, and similar verbs can change workloads or execute code. When client-certificate authentication is active, the current implementation writes certificate and private-key data to temporary files and does not remove them. Clean up any resources created by the chosen subcommand and protect or remove leftover credential files as appropriate.

## Failure modes

Missing API-server or CA configuration, invalid credentials, RBAC denial, network errors, and the normal timeout can all fail the command. Arguments are split on whitespace, so shell quoting and expansion are not interpreted as they would be by a shell.

## Implementation and tests

See [`peirates.go`](../../internal/app/peirates.go), [`kubectl_interactive.go`](../../internal/app/kubectl_interactive.go), and [`kubectl_wrappers.go`](../../internal/app/kubectl_wrappers.go). One-shot dispatch is exercised by [`module_commands_test.go`](../../internal/app/module_commands_test.go).
