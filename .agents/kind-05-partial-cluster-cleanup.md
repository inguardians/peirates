# Agent plan — clean partial Kind creations

## Finding

`test/exec-via-api-kind-integration.sh` and
`test/kubectl-try-all-kind-integration.sh` set `cluster_created=true` only
after `kind create cluster` succeeds. If creation is interrupted or leaves
partial Docker resources before returning an error, cleanup believes it owns
nothing and skips deletion.

## Goal

Mark ownership immediately before Kind creation in both scripts so partial
creation failures are cleanup-eligible without weakening existing-cluster
refusal.

## Dependencies and sequencing

The existing-cluster ownership patch establishes the intended pattern. Apply
this plan before the signal-trap and kubeconfig-isolation plans. Coordinate with
the API-exec RBAC plan because both edit
`test/exec-via-api-kind-integration.sh`.

## Owned files

- `test/exec-via-api-kind-integration.sh`
- `test/kubectl-try-all-kind-integration.sh`

## Implementation

1. Preserve `cluster_created=false` before the existing-cluster check.
2. Move `cluster_created=true` to immediately before
   `kind create cluster`.
3. Keep cleanup gated on that flag.
4. Do not set ownership before the refusal check.
5. Do not rename variables or refactor unrelated setup.

## Validation

Run:

```sh
bash -n test/exec-via-api-kind-integration.sh
bash -n test/kubectl-try-all-kind-integration.sh
git diff --check
```

Use mocked `kind` behavior for both scripts:

- Existing name: return the name from `kind get clusters`; require refusal and
  zero delete calls.
- Create failure after a partial-resource marker: return nonzero from
  `kind create cluster`; require one delete call for the exact configured name.
- Successful create followed by later setup failure: require one delete call.

No live cluster is necessary. If a live check is added, use a unique disposable
name and independently confirm cleanup.

## Acceptance criteria

- Ownership is false throughout the refusal path.
- Ownership becomes true immediately before creation.
- Both partial-create failure paths invoke exact-name cleanup.
- No unrelated RBAC, signal, kubeconfig, or assertion changes appear.

## Non-goals

- Fixing the API-exec RBAC mismatch.
- Changing trap semantics.
- Kubeconfig isolation or CI integration.
- Depending on Kind's own best-effort create-failure cleanup.

## Handoff

Report the two focused diffs, mocked invocation logs and delete counts, syntax
results, and final `git status --short`.
