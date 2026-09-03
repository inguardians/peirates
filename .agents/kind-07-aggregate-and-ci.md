# Agent plan — aggregate and continuously run Kind tests

## Finding

`make kind-test` runs only the original namespace API smoke test. The newer
dedicated Kind scripts have individual Make targets but no aggregate target,
and the GitHub workflow only builds. Broken integration scripts can therefore
land without any automated signal.

## Goal

Provide a discoverable local aggregate target and CI coverage for every
supported automated Kind test, with isolation, explicit safety controls, useful
failure output, and guaranteed exact-name cleanup checks.

## Dependencies and sequencing

This is the final plan in the series. Do not implement it until:

1. API-exec RBAC is fixed.
2. Partial-creation ownership is fixed.
3. Signal traps terminate correctly.
4. Kubeconfig isolation is complete.
5. The namespace-switch assertion is behaviorally strong.

Before editing CI, run every individual target externally and record the
baseline. Do not hide a failing test with retries, exclusions, or
`continue-on-error`.

## Owned files

- `Makefile`
- `test/README.md`
- `.github/workflows/build.yaml` or a new narrowly named Kind workflow
- A small read-only/runner helper under `test/` only if needed to avoid
  duplicating target enumeration

Do not modify individual integration-test behavior in this task.

## Implementation

### Local aggregate

1. Keep the existing `kind-test` smoke-test target backward compatible.
2. Add a clearly named aggregate target such as `kind-tests`.
3. Define the complete automated target list once, visibly, in deterministic
   order.
4. Stop on the first failure, print which target is starting, and propagate its
   exit status.
5. Exclude `kubelet-kind-manual.sh`, which intentionally retains a vulnerable
   cluster and is not an automated test.
6. Document prerequisites, expected duration/resource use, isolation, and the
   distinction between `kind-test` and `kind-tests`.

### CI

1. Use hosted ephemeral runners with a pinned supported Go version matching
   `go.mod`, plus pinned Kind and kubectl installation.
2. Prefer a matrix of individual Make targets so failures identify the broken
   scenario and jobs use isolated runners. If resource policy requires
   sequential execution, preserve per-target log boundaries.
3. Give every job a unique cluster override rather than relying on default
   names.
4. Set a job timeout and use an always-running cleanup/verification step that
   deletes only the exact job-owned cluster if it remains.
5. Upload concise diagnostics on failure, redacting service-account tokens and
   other credentials.
6. Do not expose repository or registry secrets to these tests. The anonymous
   kubelet and hostPath scenarios must remain confined to their disposable
   hosted runner.
7. Do not use `continue-on-error`, blanket retries, or a workflow-dispatch-only
   configuration as a substitute for pull-request coverage.

## Validation

Locally:

```sh
make -n kind-tests
git diff --check
```

On an isolated external workstation, run every individual target and then the
aggregate target. Record target names, durations, exit codes, starting and
ending `kind get clusters`, and any cleanup intervention.

Validate the workflow syntax with an available local checker, then inspect the
matrix expansion and cleanup conditions. If permitted, exercise the workflow
on a branch without publishing images or exposing secrets.

## Acceptance criteria

- One documented local command runs every automated Kind scenario.
- The manual vulnerable-cluster harness is excluded.
- Pull requests receive a required or clearly visible Kind result for every
  scenario.
- Failures are attributed to a specific target and fail the job.
- Each job uses unique names and private kubeconfig state.
- Always-run cleanup confirms no disposable cluster remains.
- No credentials, images, or artifacts are published.

## Non-goals

- Repairing failures discovered while enabling the suite; report them for a
  focused follow-up.
- Combining all scenarios into one long-lived shared cluster.
- Running the manual harness in CI.
- Updating unrelated build matrices, dependencies, or release workflows.

## Handoff

Provide the definitive target inventory, local and CI commands, tool versions,
matrix design, safety rationale, per-target results and durations, cleanup
evidence, and final worktree status.
