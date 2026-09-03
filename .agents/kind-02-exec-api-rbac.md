# Agent plan — fix API-exec Kind RBAC

## Finding

`test/exec-via-api-kind-integration.sh` grants `get,list` on `pods`
and `create` on `pods/exec`, then requires
`kubectl auth can-i exec pods` to return `yes`. Peirates performs that same
legacy `exec`-on-`pods` authorization check before issuing the standard
`create` request against `pods/exec`. The fixture therefore fails during
setup instead of exercising the module.

## Goal

Make the disposable test service account satisfy both the current Peirates
compatibility preflight and Kubernetes' standard pod-exec subresource
authorization, then prove both specific-pod and all-pods execution paths run.

## Dependencies and sequencing

This plan can be implemented independently of the cleanup-ownership fix. Do it
before the aggregate/CI plan so the new CI job does not begin with a known-red
test. Coordinate with the partial-cluster-cleanup plan because both edit
`test/exec-via-api-kind-integration.sh`; do not run those agents concurrently.

## Owned files

- `test/exec-via-api-kind-integration.sh`
- `test/README.md` only if its RBAC description needs correction

Do not change production authorization behavior in `internal/app` for this
task.

## Implementation

1. Preserve the existing `get` and `list` permissions on core `pods`.
2. Add the legacy `exec` verb on core `pods`, matching Peirates'
   `kubectlAuthCanI(connection, "exec", "pods")` preflight.
3. Preserve `create` on the `pods/exec` subresource, which authorizes the
   real API request.
4. Keep the setup assertions for all four permissions:
   `get pods`, `list pods`, `exec pods`, and
   `create pods --subresource=exec`.
5. Do not grant broader resources, namespaces, or cluster-scoped privileges.

## Validation

Run:

```sh
bash -n test/exec-via-api-kind-integration.sh
git diff --check
```

Then use a uniquely named disposable cluster:

```sh
PEIRATES_EXEC_API_KIND_CLUSTER=<unique-test-name> make exec-via-api-kind-test
```

Before creation, prove the name is absent. Afterward, prove cleanup removed
that exact cluster. The test must reach the marker assertions for both the
specific-pod and all-pods paths. Capture the four `auth can-i` results without
printing service-account tokens.

## Acceptance criteria

- All four setup authorization checks return `yes`.
- Numeric item `21` creates its marker only in the selected pod.
- `exec-via-api` creates its marker in every running fixture pod.
- The disposable cluster is absent after cleanup.
- No permission broader than the two required RBAC rules is introduced.

## Non-goals

- Removing Peirates' legacy authorization preflight.
- Fixing signal traps, kubeconfig isolation, or cluster ownership timing.
- Refactoring the exec module or changing CLI output.
- Running against an existing, shared, or production cluster.

## Handoff

Report the exact RBAC diff, commands and exit codes, the disposable cluster
name, marker results, cleanup confirmation, and final `git status --short`.
