# Agent plan — make Kind signal traps terminate

## Finding

The dedicated Kind scripts install the same function for `EXIT`, `INT`, and
`TERM`. Bash resumes execution when an `INT` or `TERM` trap handler returns,
so a script can continue after cleanup has deleted its cluster and temporary
files. Cleanup may also run a second time at normal shell exit.

## Goal

Ensure `INT` and `TERM` terminate each affected script with conventional
status codes while routing cleanup through the `EXIT` trap exactly once.

## Dependencies and sequencing

Start after the existing-cluster ownership patch is present. Prefer to apply
the partial-creation fix before this plan. This plan overlaps nearly every Kind
script with the kubeconfig-isolation plan, so serialize those agents: signal
handling first, kubeconfig isolation second.

## Owned files

Audit with:

```sh
rg -l 'trap cleanup EXIT INT TERM' test
```

The expected set is:

- `test/attack-hostpath-kind-integration.sh`
- `test/certificate-menu-kind-integration.sh`
- `test/curl-kind-integration.sh`
- `test/exec-via-api-kind-integration.sh`
- `test/kubectl-try-all-kind-integration.sh`
- `test/kubelet-kind-integration.sh`
- `test/kubelet-kind-manual.sh`
- `test/list-secrets-kind-integration.sh`
- `test/namespace-kind-integration.sh`
- `test/nodefs-steal-secrets-kind-integration.sh`
- `test/pod-info-kind-integration.sh`
- `test/secret-to-sa-kind-integration.sh`
- `test/service-account-kind-integration.sh`
- `test/volume-mount-kind-integration.sh`

Do not change `test/kind-integration.sh`, which already traps only `EXIT`.

## Implementation

1. Keep `cleanup` registered for `EXIT`.
2. Make `INT` exit with status 130 and `TERM` exit with status 143.
3. Let the resulting shell exit invoke the `EXIT` cleanup; do not call cleanup
   directly from both signal and exit handlers.
4. Preserve each script's existing cluster-ownership and manual-retention
   conditions.
5. Avoid a new shared helper unless it materially reduces risk without adding
   sourcing-order or mutable-global coupling.

A simple acceptable pattern is:

```sh
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
```

Use a function instead if needed to prevent recursive signal handling.

## Validation

Run `bash -n` on every changed script and `git diff --check`. Build a
temporary mocked command environment; do not create real clusters merely to
test shell signal semantics.

For every affected script:

1. Drive it past ownership acquisition into a blocking mocked command.
2. Send `TERM` to the script process.
3. Assert status 143, exactly one owned-cluster delete, temporary-file cleanup,
   and no command after the blocking point.

Test `INT` on representative automated and manual scripts and require status
130. Also test refusal before ownership and successful manual setup so the
existing cleanup semantics remain unchanged.

## Acceptance criteria

- No `trap cleanup EXIT INT TERM` remains.
- A signaled script cannot execute subsequent setup or test commands.
- Owned cleanup occurs once through `EXIT`.
- Refused pre-existing clusters remain untouched.
- The successful manual harness still retains its cluster.

## Non-goals

- Kubeconfig isolation.
- RBAC or assertion changes.
- Changing which resources cleanup owns.
- Running destructive signal tests against real clusters.

## Handoff

List all changed scripts, mocked signal cases, observed exit statuses and delete
counts, syntax results, and any platform-specific Bash behavior.
