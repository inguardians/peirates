# Discover secrets on the node filesystem

## Menu entry

- Number: `30`
- Canonical command: `nodefs-steal-secrets`
- Alias: `steal-nodefs-secrets`

## Purpose

Scan kubelet-managed pod volumes under `/var/lib/kubelet/pods/` for legacy and projected service-account tokens, certificate secrets, and other mounted Secrets.

This is a local node credential-discovery technique. Run it only on a node filesystem whose owner has authorized reading workload secrets. Discovered tokens and paths are sensitive even though the module does not print every secret value.

## Prerequisites and authorization

Peirates must run on the Kubernetes node, or in a container where the host's `/var/lib/kubelet/pods` is mounted at that exact path. Its operating-system identity must be able to traverse and read the kubelet pod-volume directories and token files.

Kubernetes API RBAC is not used by this module. Reading certificate metadata additionally requires an `openssl` executable available in `PATH`. Filesystem layout and access controls vary by Kubernetes distribution, storage implementation, and node hardening.

## Usage

Interactive menu:

```text
30
```

The canonical command and alias are equivalent. The module asks no questions.

One-shot module mode:

```text
peirates -c -m nodefs-steal-secrets
```

`30` and `steal-nodefs-secrets` are also accepted after `-m`. This path is non-interactive; `-c` is optional and only skips cloud detection.

## What it does

The scanner walks each directory beneath `/var/lib/kubelet/pods/` and inspects:

- `volumes/kubernetes.io~secret/` for legacy service-account token Secrets and other Secret volumes;
- `volumes/kubernetes.io~projected/` for directories named `kube-api-access-*` and their projected token files;
- each pod's `etc-hosts` file to infer a pod name;
- non-CA `.crt` and `.cert` files by invoking `openssl x509` and extracting their subject.

Projected tokens are parsed as JWTs and stored only when their `sub` begins with `system:serviceaccount:`. Legacy Secret-volume candidates are selected only by a directory name containing `-token-` plus readable `token` and `namespace` files; their token contents are added without JWT validation. Certificate and other Secret findings are reported with their node filesystem paths. Other Secret contents are not loaded into a general loot store by the current implementation.

Peirates also runs the same credential scanner once during startup, before dispatching the requested module. A token may therefore be reported before `Attempting menu option nodefs-steal-secrets` and treated as an existing account during the explicit second scan.

## Expected output

When the path is unavailable, menu invocation reports `Attack fails - path does not exist`. When it cannot be read, it reports `Attack fails - cannot read`.

Findings can include service-account identities, certificate subjects and paths, other Secret names and paths, and summary counts. The module does not intentionally print service-account token strings, private keys, or opaque Secret values, but its output still identifies sensitive material and exact locations.

## Side effects and cleanup

The scan is read-only on disk. It starts `openssl` subprocesses for candidate certificate files and adds newly parsed service-account tokens to the running Peirates session. No Kubernetes objects or node files are created or changed.

Clear the Peirates session and securely handle any captured output after the authorized assessment. If operators manually inspect the reported paths, that separate activity may expose secret contents and requires its own data-handling and cleanup controls.

## Failure modes

- Running inside an ordinary pod usually cannot see the host path and returns no findings.
- Filesystem permissions can make the top-level path or individual pod/Secret directories unreadable.
- CSI and other volume layouts outside the two hard-coded in-tree paths are not scanned.
- Missing or failing `openssl` prevents certificate classification; the Secret is then reported as another non-token Secret.
- Legacy token detection depends on `-token-` in the Secret directory name and the presence of both `token` and `namespace` files.
- Legacy token contents are not parsed or validated before storage, so a matching directory with arbitrary token text can be mislabeled as a service-account credential.
- Projected token detection depends on a `kube-api-access-` directory name and a JWT `sub` beginning with `system:serviceaccount:`.
- Pod-name inference from `etc-hosts` is heuristic and may return placeholder text.
- Per-file and per-directory errors are generally skipped, so a quiet or partial result does not prove that no secrets exist.
- Startup discovery can make the explicit module's service-account count appear lower than expected because duplicate tokens are not added twice.

## Implementation and tests

- [Menu registration and handler](../../internal/app/module_registry.go)
- [Aliases](../../internal/app/dispatch.go)
- [Node credential scanner](../../internal/app/config.go)
- [Node-output helper unit tests](../../internal/app/config_output_node_test.go)
- [Disposable Kind integration test](../../test/nodefs-steal-secrets-kind-integration.sh)
- [Integration-test notes](../../test/README.md)

The live integration test mounts synthetic opaque, TLS, and projected service-account fixtures in a disposable Kind node. It verifies classification and checks that token, key, and opaque values are not printed.
