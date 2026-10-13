# Find identities permitted to perform an action

## Menu entry

- **Menu item:** `kubectl-can-i` (full and short menus)
- **Canonical command:** `kubectl-can-i`
- **Maturity:** Supported

## Purpose

Print which service-account and client-certificate identities currently stored by
Peirates are authorized for a requested Kubernetes action. Each check runs the
embedded `kubectl auth can-i` using that identity's credentials. An external
kubectl binary is not required.

## Prerequisites and authorization

Peirates needs stored credentials, API-server connectivity, and valid TLS settings.
The API server must allow each identity to perform its own authorization review.
An active identity absent from the stored lists is also checked. The command uses
the actual credentials; it does not require impersonation permission.

## Usage

Enter the action at the Peirates prompt:

```text
kubectl-can-i -n namespace create pods
kubectl-can-i get secrets --namespace=production
kubectl-can-i -A list pods
kubectl-can-i get pods/example --subresource=log
kubectl-can-i get /healthz
```

For one-shot execution, quote the complete module input:

```sh
peirates -m 'kubectl-can-i -n namespace create pods'
```

Bare `kubectl-can-i` prints usage without prompting. Supply exactly a verb and a
resource, `RESOURCE/NAME`, or non-resource URL. `-n` / `--namespace` selects a
namespace; `-A` / `--all-namespaces` checks across namespaces. Otherwise the
current Peirates namespace is used. `--subresource` selects a resource subresource.
Namespace and subresource values accept separate arguments or `=value` syntax.
Arguments are split on whitespace without shell quoting or expansion.

## What it does

Peirates checks each stored service-account token and client certificate, then
prints every permitted identity. The requested operation itself is not executed.
For example, checking `create pods` asks the authorization API about permission;
it does not create a pod. The `set-auth-can-i` precheck toggle does not disable
these explicit checks. The selected identity, namespace, and stored credentials
remain unchanged.

## Expected output

Permitted identities are labeled by credential type and stored name:

```text
[+] Permitted: service account "example"
[+] Permitted: certificate "operator"
```

The command also reports a summary. Failed checks are reported separately from
denials, so an unreachable API server or invalid credential is not presented as a
confirmed denial. Tokens, private keys, and certificate contents are not printed.

## Side effects and cleanup

The command sends authorization and discovery requests to the Kubernetes API.
These requests may appear in API audit logs. No workloads are created or changed,
and no session identity switch occurs. Each check uses an isolated temporary
kubeconfig with restrictive permissions; its directory and discovery cache are
removed after the check. Authorization approval alone does not
guarantee that admission policy or other runtime checks will allow the operation.

## Failure modes

Invalid arguments print an error without checking identities. Connection and
authentication failures affect the relevant identity and the remaining checks
continue. Identity, server, kubeconfig, impersonation, and other kubectl override
flags are rejected; use the Peirates context menus to configure connection state.
`--list` is not supported because this command checks one specific action.

## Implementation and tests

See the [menu handler](../../internal/app/kubectl_can_i.go),
[authorization module](../../internal/modules/kubectlcani/kubectl_can_i.go),
[handler tests](../../internal/app/kubectl_can_i_test.go), and
[one-shot command tests](../../internal/app/module_commands_test.go).
