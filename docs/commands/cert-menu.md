# Certificate authentication menu

## Menu entry

- Number: `9`
- Canonical command: `cert-menu`
- Aliases: none beyond numeric entry `9`
- Maturity: Stable for discovered kubelet credentials; list and switch have live Kind node coverage.

## Purpose

List client certificate/private-key pairs discovered by Peirates and select one as the active Kubernetes authentication context.

## Prerequisites and authorization

Peirates must have discovered at least one readable kubelet kubeconfig containing or referencing a client certificate and private key. Startup checks the kubelet command line and several conventional kubeconfig paths. Accessing these node credentials usually requires node-level filesystem visibility and should only be done during an authorized assessment.

The certificate's Kubernetes identity and RBAC grants determine what subsequent operations can do.

## Usage

At the main prompt, enter `9` or `cert-menu`, then choose:

```text
1 / list      list discovered certificate/key pairs
2 / switch    select a pair by index
```

Module mode is supported, but the action and switch index are still read from stdin:

```sh
peirates -m cert-menu
```

## What it does

List prints the stored pair names. Switch installs the chosen pair's certificate, private key, API server, and CA in the active connection. It writes the CA certificate to a temporary `/tmp/*-ca.crt` file, sets the namespace to `default`, and clears active service-account token fields. Startup automatically selects the first discovered pair when no service account is available, so that CA-file side effect can occur before the menu action.

Subsequent Kubernetes commands write the selected client certificate and private key to additional temporary files for kubectl arguments.

## Expected output

The menu shows the current certificate name and indexed discovered pairs. A successful switch prints `Selected NAME`. Discovery at startup may separately print `Found Kubelet certificate and secret key: NAME`.

## Side effects and cleanup

Switching changes the API server, CA path, namespace, and authentication method for the current process. It writes sensitive authentication material to temporary files. The CA file and the later kubectl certificate/key files are not explicitly removed by the implementation.

Switch to a service account to clear certificate fields in memory, exit Peirates, and securely remove leftover Peirates temporary credential files according to your environment's procedures. Do not delete unrelated files matching broad `/tmp` patterns.

## Failure modes

- With no discovered pairs, list is empty and any switch index is rejected.
- Non-numeric and out-of-range selections are rejected.
- Discovery can fail on unreadable or missing kubeconfig and credential files. Malformed or unexpectedly structured YAML can trigger a process panic because several parsed fields use unchecked type assertions.
- Switching can fail if Peirates cannot create or write the temporary CA file; CA-file creation failure is fatal through `log.Fatal`.
- The menu does not validate the certificate, key, server, or authorization before selecting them.
- Authorization prechecks are bypassed for certificate contexts, so subsequent API failures are reported by the operation itself.

## Implementation and tests

- [Certificate submenu](../../internal/app/menu_cert_auth.go)
- [Credential discovery and connection assignment](../../internal/app/config.go), [service-account utilities](../../internal/app/service_account_utils.go)
- [kubectl certificate temp files](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/service_account_utils_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind node integration test](../../test/certificate-menu-kind-integration.sh)
