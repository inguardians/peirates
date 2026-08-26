# Import a service-account token from a Secret

## Menu entry

- Number: `11`
- Canonical command: `secret-to-sa`
- Alias: `get-secret`
- Maturity: Stable for legacy service-account-token Secrets; live Kind tests cover import, aliasing, and type rejection.

## Purpose

Fetch a named Kubernetes Secret, decode its service-account token, and add that credential to Peirates' in-memory service-account collection.

## Prerequisites and authorization

Peirates needs a working Kubernetes connection and `get` permission on the named Secret in the current namespace. It does not need `list` permission when the name is already known, and this handler does not perform a SelfSubjectAccessReview before requesting the Secret.

This command extracts and prints a live authentication credential. Use it only in an explicitly authorized assessment and protect its output.

## Usage

At the interactive prompt, enter `11`, `secret-to-sa`, or `get-secret`, then enter the exact Secret name.

Module mode is supported but still reads the Secret name from stdin:

```sh
peirates -m secret-to-sa
```

In module mode the imported account disappears when the process exits, although the decoded token is still printed. Use interactive mode if a later command in the same session must use the imported account.

## What it does

Peirates runs the equivalent of `kubectl get secret NAME -o json` in the current namespace. It requires the Secret type to equal `kubernetes.io/service-account-token`, base64-decodes `data.token`, prints the decoded token, and adds it to the service-account collection under the Secret name with discovery method `Cluster Secret`.

It does not automatically switch the active Kubernetes context to the imported token. Use the service-account menu or `switch-sa` afterward.

## Expected output

On success, output includes:

```text
[+] Saved SECRET_NAME // FULL_DECODED_TOKEN
```

This is intentionally sensitive output. A non-token Secret produces `This secret is not a service account token`.

## Side effects and cleanup

The Kubernetes request is read-only, but the decoded credential is retained in process memory and exposed on stdout, terminal scrollback, and any output capture. Duplicate names are not added, although the token is printed before duplicate detection.

When client-certificate authentication is active, the shared kubectl wrapper writes the certificate and private key to temporary `/tmp/peirates-*` files and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

Exit Peirates to discard the stored account and securely handle or remove captured credential output. This command does not revoke the Kubernetes token.

## Failure modes

- Missing input or a failed Kubernetes request returns without adding an account.
- Non-token Secret types are rejected.
- Invalid base64 token data reports a decode error.
- The JSON parser uses unchecked type assertions for `type`, `data`, and `token`; malformed or unexpectedly shaped Secret JSON can panic the process.
- Duplicate detection is based on trimmed Secret name, not token value.
- Modern projected bound tokens usually are not stored in service-account-token Secrets, so there may be no suitable Secret to import.

## Implementation and tests

- [Secret retrieval, decoding, and account storage](../../internal/app/service_account_utils.go)
- [Kubernetes command wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Service-account unit tests](../../internal/app/service_account_utils_test.go)
- [Module smoke tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/secret-to-sa-kind-integration.sh)
