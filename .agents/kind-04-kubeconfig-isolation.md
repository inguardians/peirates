# Agent plan — isolate Kind kubeconfig state

## Finding

Most dedicated Kind scripts pass `--context` to kubectl but allow
`kind create cluster` and `kind delete cluster` to write the caller's default
kubeconfig. Creation changes the current context, and deletion does not restore
the caller's prior context.

## Goal

Run every automated Kind test with a private temporary kubeconfig so the
caller's kubeconfig bytes and current context remain unchanged. Give the manual
kubelet harness a private retained kubeconfig that remains usable with its
intentionally retained cluster.

## Dependencies and sequencing

Apply after the ownership, partial-creation, and signal-trap plans. It overlaps
all dedicated scripts, so it must not run concurrently with those agents.
Complete this before adding aggregate CI execution.

## Owned files

- Every automated `test/*-kind-integration.sh` except
  `test/kind-integration.sh`, which already exports a temporary kubeconfig
- `test/kubelet-kind-manual.sh`
- `test/README.md` for the manual kubeconfig handoff and any general isolation
  statement
- `test/kind-build-helpers.sh` only if a small kubeconfig helper is clearly
  safer than duplicating lifecycle code

Do not change Go production code or Kubernetes fixtures.

## Implementation

### Automated scripts

1. Create a restrictive temporary kubeconfig path before Kind creation.
2. Export `KUBECONFIG` or consistently pass Kind's `--kubeconfig` flag and
   kubectl's `--kubeconfig` flag. Do not mix isolated and default-config calls.
3. Keep the private kubeconfig available until after cluster deletion.
4. Remove only the kubeconfig created by that script.
5. Ensure refusal before ownership cannot alter the caller's kubeconfig.

### Manual kubelet harness

The manual script retains a live cluster, so deleting its private kubeconfig on
successful exit would make the handoff unusable.

1. Accept an optional, clearly named kubeconfig override such as
   `PEIRATES_KUBELET_MANUAL_KUBECONFIG`.
2. If no override is supplied, create a restrictive unique kubeconfig and track
   whether the script owns that file.
3. On failed setup, delete the owned partial cluster and remove only an owned
   generated kubeconfig.
4. On successful setup, retain the kubeconfig, print its exact path, and show
   all follow-up and deletion commands with `KUBECONFIG=<path>`.
5. Never remove or overwrite a user-supplied kubeconfig.

## Validation

Run `bash -n` on every changed script and `git diff --check`.

Use a sentinel caller kubeconfig containing a known context and record:

```sh
sha256sum <sentinel-kubeconfig>
kubectl --kubeconfig <sentinel-kubeconfig> config current-context
```

With mocked Kind/kubectl, cover refusal, create failure, normal automated
cleanup, failed manual setup, and successful manual setup. Assert the sentinel
checksum and current context never change.

When Docker and Kind are available, run at least one automated test with a
unique cluster name while the sentinel is the caller's `KUBECONFIG`. Confirm
the test succeeds, its cluster and private kubeconfig are removed, and the
sentinel remains byte-identical. Exercise the manual success lifecycle only
with an explicitly disposable name; confirm its printed private kubeconfig
works before deleting that exact cluster and owned config.

## Acceptance criteria

- Automated scripts never modify the caller's kubeconfig or current context.
- Their private kubeconfigs are removed after cluster cleanup.
- Manual successful setup retains and clearly reports a working private
  kubeconfig.
- Failure removes only owned generated files and clusters.
- `test/kind-integration.sh` retains its existing behavior.

## Non-goals

- Signal handling, RBAC, assertion strength, or CI changes.
- Reusing a shared or production kubeconfig.
- Deleting a user-supplied manual kubeconfig.
- Changing cluster names or Kubernetes permissions.

## Handoff

Report the chosen isolation mechanism, affected scripts, sentinel checksums and
contexts before/after, live disposable names, retained-manual handoff behavior,
cleanup evidence, and final worktree status.
