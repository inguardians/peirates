# List Secrets

## Menu entry

- Number: `10`
- Canonical command: `list-secrets`
- Alias: `get-secrets`
- Maturity: Stable; success, denial, Secret types, and aliases have live Kind coverage.

## Purpose

List Secret names in the current Kubernetes namespace and separately identify Secrets whose type is `kubernetes.io/service-account-token`.

## Prerequisites and authorization

Peirates needs a working Kubernetes connection and permission to list Secrets in the current namespace. With authorization prechecks enabled, it first submits a SelfSubjectAccessReview for `get` on `secrets`.

Secret names and types are sensitive cluster metadata. Only enumerate them in a namespace you are authorized to assess.

## Usage

At the interactive prompt, enter `10`, `list-secrets`, or `get-secrets`.

The command has no prompts and is suitable for module mode:

```sh
peirates -m list-secrets
```

## What it does

Peirates runs the equivalent of `kubectl get secrets -o json` in the current namespace. The API response contains each returned Secret's `data`, but Peirates parses only the name and type and does not print or retain those data values. It prints every name once as a Secret, then prints service-account-token Secret names again under a service-account label.

## Expected output

Each Secret produces:

```text
[+] Secret found: SECRET_NAME
```

Each legacy service-account-token Secret also produces:

```text
[+] Service account found: SECRET_NAME
```

Clusters using projected bound service-account tokens may have no Secrets of that legacy type.

## Side effects and cleanup

This is a read-only Kubernetes operation. It does not retain Secret contents or change authentication context. Names are exposed to stdout and any surrounding logs; protect captured output as sensitive metadata. No cluster cleanup is required.

When client-certificate authentication is active, the shared kubectl wrapper writes the certificate and private key to temporary `/tmp/peirates-*` files and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

## Failure modes

- A denied authorization precheck prints `Permission Denied` and discloses no names.
- Kubernetes request, authentication, TLS, or JSON parsing failures return empty results.
- The precheck asks about `get`, while listing the Secret collection normally requires `list`; the request can fail even after the precheck succeeds.
- Client-certificate contexts bypass the authorization precheck.

## Implementation and tests

- [Command output](../../internal/app/list_secrets.go)
- [Secret enumeration and parsing](../../internal/app/enumerate_simple_objects.go)
- [Kubernetes command wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/enumerate_simple_objects_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/list-secrets-kind-integration.sh)
