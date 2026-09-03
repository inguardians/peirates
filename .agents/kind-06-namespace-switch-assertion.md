# Agent plan — prove namespace switching changes behavior

## Finding

The namespace integration test asserts that the target namespace appears in
switch output, but the switch function lists every namespace before reading
input. If input is ignored or read as empty, the target is already present and
the test can pass without assigning the new namespace.

## Goal

Make the live test observe a namespace-scoped API result that is available only
after the requested switch, proving the same Peirates session changed its
active namespace.

## Dependencies and sequencing

Apply after signal and kubeconfig work because those plans also edit the
namespace script. It may be implemented before or after aggregate CI, but the
aggregate plan must not be considered complete until this strengthened test
passes.

## Owned files

- `test/namespace-kind-integration.sh`
- `test/README.md` if the fixture or assertion description changes

Avoid production changes unless the integration behavior is impossible to
observe without one; request review before changing CLI output.

## Implementation

1. Preserve the existing namespace-list test.
2. Create a uniquely named fixture pod or ConfigMap in
   `target_namespace`, not in the runner's starting namespace.
3. Grant the runner service account only the narrow cross-namespace permission
   needed to read that fixture after switching.
4. Drive the full interactive Peirates session rather than a one-shot
   `-m ns-menu` process:
   - enter the namespace menu;
   - choose switch;
   - supply `target_namespace`;
   - continue in the same process;
   - run a namespace-scoped command that reports the target-only fixture;
   - exit cleanly.
5. Assert the target-only fixture appears after the switch. Partition output if
   necessary so its earlier setup/list text cannot satisfy the assertion.
6. Assert the starting namespace does not contain the fixture and that the
   service account is authorized only for the intended target read.

A target-only pod followed by main-menu pod listing is preferred because it
directly exercises the session's `ServerInfo.Namespace`.

## Validation

Run:

```sh
bash -n test/namespace-kind-integration.sh
git diff --check
PEIRATES_NAMESPACE_KIND_CLUSTER=<unique-test-name> make namespace-kind-test
```

Before the live run, prove the name is absent. Afterward, prove the exact
cluster was removed. Add a negative mocked or fixture variant showing that an
empty/ignored switch input cannot satisfy the new target-only assertion.

## Acceptance criteria

- Namespace listing still reports both fixture namespaces.
- The switch and follow-up API action happen in one Peirates process.
- The target-only resource is observed only after switching.
- A no-op or ignored switch causes the test to fail.
- RBAC remains narrowly scoped and cleanup succeeds.

## Non-goals

- Adding a new production success message solely for the test.
- Changing namespace-selection semantics.
- Fixing signal traps, kubeconfig state, or unrelated menu tests.
- Granting broad cluster-wide pod access.

## Handoff

Report the fixture and RBAC design, exact interactive input sequence, the
behavioral proof, negative-check result, live cluster name, cleanup evidence,
and final status.
