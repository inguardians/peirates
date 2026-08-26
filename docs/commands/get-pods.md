# Get pods

## Menu entry

- Number: `3`
- Canonical command: `get-pods`
- Alias: `list-pods`
- Maturity: Stable; covered by unit, module, and live Kind tests.

## Purpose

Print the names of pods in the current namespace.

## Prerequisites and authorization

Peirates needs a working Kubernetes connection and permission to list pods in the current namespace. With authorization prechecks enabled, it first submits a SelfSubjectAccessReview for `get` on `pods`.

## Usage

At the interactive prompt, enter `3`, `get-pods`, or `list-pods`.

The command needs no prompts and is suitable for module mode:

```sh
peirates -m get-pods
```

## What it does

Peirates runs the equivalent of `kubectl get pods -o json` in the current namespace, parses `items[].metadata.name`, and prints each name. It does not restrict results to Running pods despite the internal variable name `runningPods`.

## Expected output

After a heading, each result is printed as:

```text
[+] Pod Name: POD_NAME
```

An empty namespace produces the heading and no pod lines.

## Side effects and cleanup

This is a read-only Kubernetes operation. It does not retain pod details or modify process context. When client-certificate authentication is active, however, the shared kubectl wrapper writes the certificate and private key to temporary `/tmp/peirates-*` files and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

## Failure modes

- A denied authorization precheck prints `Permission Denied` and no names.
- API, TLS, authentication, or JSON parsing failures produce an error and no names.
- The precheck asks about `get`, while listing the pod collection normally requires `list`; the operation can fail after a successful precheck.
- Client-certificate contexts bypass the authorization precheck.

## Implementation and tests

- [Pod enumeration](../../internal/app/enumerate_simple_objects.go)
- [Kubernetes command wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/enumerate_simple_objects_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/pod-info-kind-integration.sh)
