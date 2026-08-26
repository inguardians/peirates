# Dump pod information

## Menu entry

- Number: `4`
- Canonical command: `dump-pod-info`
- Alias: `dump-podinfo`
- Maturity: Stable; covered by unit, module, and live Kind tests.

## Purpose

Retrieve and print the complete JSON representation of pods in the current namespace, then retain the parsed subset used by other Peirates features.

## Prerequisites and authorization

Peirates needs a working Kubernetes connection and permission to list pods in the current namespace. With authorization prechecks enabled, it first submits a SelfSubjectAccessReview for `get` on `pods`.

Pod specifications can disclose operationally sensitive metadata such as images, environment-variable definitions, node placement, volume sources, and Secret or ConfigMap references.

## Usage

At the interactive prompt, enter `4`, `dump-pod-info`, or `dump-podinfo`.

The command has no prompts and is suitable for module mode:

```sh
peirates -m dump-pod-info
```

## What it does

Peirates runs the equivalent of `kubectl get pods -o json` in the current namespace. It prints the raw response and unmarshals it into the session's pod-details structure. The stored structure is used by features such as hostPath discovery.

## Expected output

Successful output includes a retrieval heading, the full pod-list JSON, and:

```text
[+] Retrieving details for all pods was successful:
```

The command may print a successful retrieval message followed by an unmarshalling error if the response is not compatible with the expected structure.

## Side effects and cleanup

The Kubernetes operation is read-only. Parsed pod details remain in memory for the current process. Raw JSON is written to stdout and may be captured in terminal logs; handle it according to the sensitivity of cluster metadata. Exit Peirates to discard retained details.

When client-certificate authentication is active, the shared kubectl wrapper writes the certificate and private key to temporary `/tmp/peirates-*` files and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

## Failure modes

- A denied authorization precheck stops the request.
- API, TLS, authentication, or kubectl failures print `Unable to retrieve details`.
- Malformed JSON is printed and then reports an unmarshalling error.
- The precheck asks about `get`, but retrieving the pod collection normally requires `list`.
- Client-certificate contexts bypass the authorization precheck.

## Implementation and tests

- [Pod-detail retrieval](../../internal/app/enumerate_simple_objects.go)
- [Pod data model](../../internal/model/kubernetes.go)
- [Kubernetes command wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/enumerate_simple_objects_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/pod-info-kind-integration.sh)
