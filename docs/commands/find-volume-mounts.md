# Find volume mounts

## Menu entry

- Number: `5`
- Canonical command: `find-volume-mounts`
- Alias: `find-mounts`
- Maturity: Stable for `hostPath` discovery; its broader “volume mounts” name is misleading.

## Purpose

Identify `hostPath` volume sources declared by pods in the current namespace. Despite the menu wording, this command does not report every Kubernetes volume or container mount path.

## Prerequisites and authorization

Peirates needs a working Kubernetes connection and permission to list pods in the current namespace. With authorization prechecks enabled, it first checks `get` on `pods` through a SelfSubjectAccessReview.

Host filesystem paths can reveal sensitive node layout and potential privilege-escalation targets. Use this feature only within an authorized assessment.

## Usage

At the interactive prompt, enter `5`, `find-volume-mounts`, or `find-mounts`, then select:

```text
1 / all       show hostPath sources for all pods
2 / single    show hostPath sources for one named pod
```

Module mode is supported but remains stdin-driven:

```sh
peirates -m find-volume-mounts
```

For `single`, provide the pod name at the second prompt.

## What it does

Before acting on the selection, Peirates retrieves `kubectl get pods -o json`, prints that complete JSON, and stores parsed pod details. It then traverses `spec.volumes[].hostPath.path`. `all` prints each non-empty path with its pod name; `single` filters by exact pod name and prints its paths.

It does not inspect `containers[].volumeMounts[].mountPath`, PVC contents, projected volumes, or other volume types.

## Expected output

For `all`, each finding resembles:

```text
Host Mount Point: /host/path found for pod POD_NAME
```

For `single`, Peirates prints the chosen pod name and then one `Host Mount Point` line per finding. No explicit “none found” result is emitted.

## Side effects and cleanup

This is a read-only Kubernetes operation. Pod details remain in process memory, and full pod JSON is exposed on stdout even though the user requested only mount information. No cluster cleanup is required; exit Peirates to discard retained details.

When client-certificate authentication is active, the shared kubectl wrapper writes the certificate and private key to temporary `/tmp/peirates-*` files and does not remove them. Remove only files confirmed to belong to the authorized Peirates run.

## Failure modes

- Missing input or a read error returns without a scan. Any successfully read non-empty value, including an invalid selection, triggers pod retrieval and full JSON output before the selection is evaluated; an invalid value then produces no mount report.
- A denied permission check or failed pod request leaves no useful pod data, but the selected reporting branch can still run and show no findings.
- A nonexistent pod name produces no error and no findings.
- The precheck asks about `get`, while the collection request normally needs `list`.
- The `single` branch does not check the error returned while reading the pod name.
- Client-certificate contexts bypass the authorization precheck.

## Implementation and tests

- [Retrieval and hostPath reporting](../../internal/app/enumerate_simple_objects.go)
- [Pod data model](../../internal/model/kubernetes.go)
- [Kubernetes command wrapper](../../internal/app/kubectl_wrappers.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/enumerate_simple_objects_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/volume-mount-kind-integration.sh)
