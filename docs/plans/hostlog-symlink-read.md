# Writable host-log symlink-read implementation plan

Status: **IMPLEMENTED AND LIVE-VALIDATED.** The maintainer authorized
multi-agent implementation on 2026-09-18 under the command contract and safety
boundaries below. The focused scanner and host-log action Kind gates passed on
the same date and deleted their disposable clusters.

Implementation note: the live Kind gate showed that Kubernetes runtime staging
can replace mountinfo's `/var/log` root with a runtime-specific volume path.
The shipped qualifier therefore retains root-based detection for nonstandard
container destinations and adds one narrow fallback for a writable direct mount
placed exactly at container path `/var/log`. That fallback is always labeled as
having unproven hostPath origin; arbitrary destinations remain rejected.

## Goal

Add a bounded Peirates capability for a container that already has a writable
host `/var/log` directory, or a descendant of that directory, mounted into the
container. The first release will:

1. Extend `container-escape-scan` with a strictly read-only finding for the
   local mount prerequisite.
2. Add one explicit action that reads one operator-selected host path through
   the kubelet system-log file server.
3. Prove the behavior and cleanup against a disposable Kind node.

The Aqua article demonstrates two related behaviors:

- Replacing a container's CRI `0.log` link and requesting `pods/log`, which may
  expose host-file data through the CRI parser or its error output.
- Creating a symlink below the mounted host `/var/log` and requesting that path
  through kubelet's `/logs/` handler.

The first release uses the second behavior because it does not alter an active
container log. It creates one temporary symlink pointing directly to the
requested path rather than linking to host `/`; this provides the same
single-file read primitive with narrower exposure.

Primary references:

- [Aqua: Kubernetes Pod Escape Using Log Mounts](https://www.aquasec.com/blog/kubernetes-security-pod-escape-log-mounts/)
- [Original kube-pod-escape proof of concept](https://github.com/danielsagi/kube-pod-escape)
- [Kubernetes kubelet `/logs/` handler](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/kubelet/kubelet.go#L1885-L1919)
- [Kubernetes CRI log reader](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/cri-client/pkg/logs/logs.go)
- [Kubernetes system-log query documentation](https://kubernetes.io/docs/concepts/cluster-administration/system-logs/#log-query)
- [Kubernetes `hostPath` warnings](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)

## Proposed first-release contract

The following values are proposed and must be frozen before parallel work
starts:

| Item | Value |
|---|---|
| Menu item | `33` |
| Canonical command | `hostlog-symlink-read` |
| Alias | `hostlog-read` |
| Scanner technique | `hostlog-symlink-read` |
| Menu text | Read one host file through a writable host-log mount and the kubelet log proxy |
| Default response limit | 1 MiB |
| Default request timeout | 10 seconds |
| Error-body limit | 4 KiB |
| Initial transport | Authenticated API-server `nodes/proxy` |

Menu item 28 remains reserved for the detection-only cgroup release-agent
technique documented in `docs/plans/container-escapes.md`. Item 33 is the next
unassigned number after the implemented item 32.

The action accepts interactive, line-oriented input for:

1. A mounted host-log path. Auto-select only when exactly one candidate exists.
2. A node name. Offer `NODE_NAME` as a default when the environment provides
   it; do not infer the node from the container hostname.
3. One absolute host target path. Provide no default target.

The target path itself constitutes the operator's explicit selection. The
command must warn that it can expose sensitive node data before printing the
response. Existing flags, direct `-m` behavior, and menu input semantics remain
unchanged.

## Scope boundaries

The first release includes:

- Local, read-only detection through `/proc/self/mountinfo`.
- Exact `/var/log` and normalized descendant mount roots.
- Read-write and effective write/search-access checks.
- Authenticated access through the API-server node proxy.
- Bearer-token and client-certificate session authentication.
- CA data or CA file verification and the existing explicit `IgnoreTLS` mode.
- One unique temporary symlink and bounded response handling.
- Linux implementation and stable unsupported-platform behavior.
- Unit, command-contract, safe shell, and live Kind tests.

The first release does not include:

- Direct kubelet-IP access.
- CRI `0.log` replacement through `pods/log`.
- Recursive filesystem listing or automatic sensitive-file searches.
- Integration with startup credential discovery or `nodefs-steal-secrets`.
- Cross-pod log harvesting as a separate command.
- Log deletion, truncation, injection, or rotation manipulation.
- Node disk-pressure generation.
- Log-collector symlink manipulation.
- Pod creation, reverse shells, persistence, or changes to host files other
  than the temporary symlink.

These require separate authorization and runtime-specific plans after the
single-file read primitive has passed its live gate.

## Detection design

Add a shared mount qualifier beside `HostRootCandidates` in
`internal/modules/escapeutil/mountinfo.go`:

```go
type HostLogMount struct {
	MountPoint string
	Root       string
	URLPrefix  string
}

func HostLogCandidates(mounts []Mount) []HostLogMount
```

The final names may change at the contract gate, but the returned data must
retain all three concepts:

- `MountPoint`: the container-visible path, such as `/mnt/node-logs`.
- `Root`: the mount's node-log root, such as `/var/log` or
  `/var/log/containers`.
- `URLPrefix`: the path below kubelet `/logs/`, empty for `/var/log` and
  `containers` for `/var/log/containers`.

Qualification rules:

- Accept `/var/log` and true path-segment descendants.
- Reject `/var/logger`, `/var/log-old`, relative roots, and relative mount
  points.
- Preserve overlay-backed candidates because a Kind node's filesystem can
  expose a valid hostPath through overlay storage.
- Require exact `rw` in per-mount options for an actionable local candidate.
- Require that the mount point is a direct directory rather than a symlink.
- Check write and search access without creating a test file or symlink.
- Sort and de-duplicate candidates deterministically.

Effective UID 0 is useful evidence but is not a hard requirement. Group
permissions or an assigned filesystem group can make the mount writable.

Add `TechniqueHostLogSymlinkRead = "hostlog-symlink-read"` to the existing
scanner. The scanner must remain strictly local and read-only: no Kubernetes
credentials, network calls, directory enumeration, test files, symlinks, or
target-file reads.

Finding behavior:

- `candidate`: at least one directory is rooted at `/var/log` or a descendant,
  has an effective `rw` mount, and permits write/search access. The scanner
  cannot prove endpoint enablement or authorization.
- `blocked`: mountinfo is unavailable or every candidate is read-only,
  inaccessible, malformed, or not a direct directory.
- `unsupported`: the platform does not support the Linux primitive.

Multiple qualifying mounts remain `candidate`, with evidence that the action
requires explicit selection. The existing deterministic finding order must be
preserved with this new finding added once on Linux and unsupported builds.

## Action module design

Create `internal/modules/hostlog` with Linux and unsupported-platform files.
The package must not import `internal/app`.

The package contract should express these concepts:

```go
type Fetcher interface {
	Probe(context.Context) error
	Read(context.Context, string) ([]byte, error)
}

type Options struct {
	MountPoint string
	TargetPath string
	RunID      string
	Fetcher    Fetcher
}

type Result struct {
	MountPoint  string
	HostLogRoot string
	LogPath     string
	Content     []byte
}

func Probe(context.Context) ([]escapeutil.Finding, error)
func ReadFile(context.Context, Options) (Result, error)
```

`RunID` exists as a deterministic unit-test seam. Production code generates it
from a cryptographically secure source and validates the resulting basename.

`ReadFile` performs this sequence:

1. Validate that the target is absolute, normalized, non-empty, and not `/`.
2. Re-read `/proc/self/mountinfo`; do not trust a prior scanner result.
3. Re-run mount root, `rw`, directory, and write/search qualification.
4. Auto-select only one candidate, or match the exact normalized mount point
   supplied by the operator. Fail closed on ambiguity.
5. Call `Fetcher.Probe` before mutation so RBAC, TLS, proxy, or disabled-handler
   failures do not leave a symlink.
6. Open the mount directory with no-follow, directory-only, and close-on-exec
   protections. Reuse `escapeutil.OpenDirectoryNoFollow` where its contract is
   sufficient.
7. Generate a `.peirates-hostlog-<run-id>` basename and refuse any existing
   entry.
8. Create a symlink relative to the open directory descriptor with
   `symlinkat`. Its target is the exact requested absolute path.
9. Record the link's no-follow identity and target, then install cleanup before
   making the network request.
10. Fetch the kubelet-relative link through the injected fetcher.
11. Before `unlinkat`, verify that the entry is still the same symlink and has
    the expected target. Refuse to remove a replaced object.
12. Return exact response bytes only after cleanup succeeds. If both fetch and
    cleanup fail, preserve both errors and make the cleanup failure prominent.

For a mount rooted at `/var/log`, the requested log path is only the temporary
basename. For a mount rooted at `/var/log/pods`, it is
`pods/<temporary-basename>`. URL construction belongs to the transport adapter;
the hostlog package returns path components rather than concatenating an
unescaped URL.

Normal return, HTTP failure, timeout, context cancellation, and handled INT or
TERM must all execute cleanup. Documentation must state that an uncatchable
SIGKILL, process crash, node loss, or filesystem failure can leave the
temporary link behind.

## Kubernetes raw transport

Add a bounded arbitrary-byte request path under `internal/kube`; do not use the
JSON-only `DoAPIRequest`, the output-aggregating kubectl wrapper, or
`executeKubeletCommand`.

The client API should accept a context, `ServerInfo`, HTTP method, API path,
timeout, success-body limit, and error-body limit. It must:

- Use the configured API-server URL.
- Support bearer tokens and in-memory client certificate/key pairs.
- Trust `CACertData` or `CAPath` and fail closed when verification is required
  but cannot be configured.
- Honor the existing explicit `IgnoreTLS` setting and annotate the gosec
  exception at the exact TLS construction.
- Disable redirects.
- Stop at `max+1` bytes and return a stable oversized-response error.
- Bound and sanitize non-2xx bodies without leaking credentials.
- Preserve context cancellation and close every response body.
- Never print tokens, certificates, request headers, or response data.

Add a subresource-aware access review that can express:

```text
verb=get, group="", resource=nodes, subresource=proxy, namespace=""
```

Respect the existing `UseAuthCanI` setting. When checks are enabled, denial
must stop before `Fetcher.Probe` and before filesystem mutation. When checks are
disabled, the actual bounded endpoint probe remains authoritative.

The app-layer fetcher uses only:

```text
/api/v1/nodes/{node}/proxy/logs/
/api/v1/nodes/{node}/proxy/logs/{escaped-path-components}
```

Escape the node and every path component independently. The probe should
verify that the route is enabled without retaining or displaying a directory
listing. Distinguish at least authorization denial, handler/route absence, TLS
failure, timeout, and oversized response.

## Application and documentation integration

Add a stream-testable launcher in
`internal/app/container_escape_modules.go`, following the existing launcher
pattern and using complete line-oriented input so piped responses are not read
ahead or discarded.

Register and advertise the command in:

- `internal/app/module_registry.go`
- `internal/app/dispatch.go`
- `internal/app/menu.go`
- `internal/app/module_commands_test.go`
- `internal/ui/menu.go`
- `internal/ui/completion.go`
- `internal/ui/completion_test.go`
- `docs/commands/hostlog-symlink-read.md`
- `docs/commands/README.md`
- `docs/commands/manifest.tsv`

No private worker or `internal/app/run.go` change is required because the action
does not change namespaces, roots, or process credentials.

The command output must identify:

- Selected mount and node.
- Target path.
- Whether the API proxy preflight succeeded.
- The bounded returned content.
- Successful link removal, or an explicit cleanup failure.
- The boundary reached: the Kind-node container or Kubernetes node hosting the
  kubelet, not an unproven physical machine.

Do not print the active bearer token, client key, certificate data, or generated
authorization headers. Treat command output as sensitive because the selected
file content may contain credentials.

## Unit and command-contract tests

Mount qualification tests must cover:

- Exact `/var/log` and descendants such as `/var/log/pods`.
- Similar string prefixes that must not qualify.
- Deterministic ordering and de-duplication.
- Overlay-backed mounts.
- Read-only, relative, malformed, symlink, non-directory, and inaccessible
  candidates.
- Non-root callers with effective write/search access.

Scanner tests must cover:

- One new finding on Linux and unsupported platforms.
- Candidate output for one and multiple writable mounts.
- Blocked output for missing mountinfo, read-only mounts, and denied access.
- Stable finding order and deterministic evidence.
- Proof that the scan creates no files, walks no directories, makes no network
  request, and reads no target-file contents.

Hostlog action tests must cover:

- Correct kubelet-relative paths for `/var/log` and nested roots.
- Exact response bytes and cleanup after success.
- Cleanup after fetch failure and context cancellation.
- No mutation when authorization or endpoint probe fails.
- No overwrite or deletion on basename collision.
- Rejection of empty, relative, non-normalized, and root targets.
- Rejection of changed or ambiguous mounts immediately before mutation.
- Refusal to unlink an entry whose identity or target changed.
- Cleanup errors preserved alongside the primary error.
- Stable unsupported-platform compilation and errors.

Raw transport tests must use `httptest` and cover:

- Bearer and client-certificate authentication.
- CA data, CA file, verification failure, and explicit insecure TLS.
- Exact node-proxy route and escaping.
- Subresource-aware SelfSubjectAccessReview request fields.
- Redirect refusal, HTTP 403, HTTP 404, timeout, cancellation, partial bodies,
  oversized success bodies, and bounded error bodies.

Application tests must cover:

- `33`, `hostlog-symlink-read`, and `hostlog-read` reaching one handler.
- All three prompts, defaults, EOF, invalid input, and piped multiline input.
- Errors before action invocation when mount, node, or target input is invalid.
- Menu, completion, registry, command documentation, and manifest parity.

## Disposable Kind test design

Extend `test/container-escape-scan-kind-integration.sh` for detection and add
`test/hostlog-read-kind-integration.sh` for the mutating action. The current
automated inventory contains 19 targets; adding the new action target changes
the required parity to 20 Make targets, 20 workflow entries, and 20 executable
`*kind-integration.sh` scripts.

The new script uses:

- Target: `hostlog-read-kind-test`.
- Cluster variable: `PEIRATES_HOSTLOG_READ_KIND_CLUSTER`.
- Default name: `peirates-hostlog-read-integration`.
- A single control-plane Kind node and no host `extraMounts`.
- The current pinned node image from `kind-build-helpers.sh`.
- A private mode-0600 kubeconfig.
- `run_kind_script_with_signal_forwarding`.
- A private cluster claim, fail-closed absent-cluster check,
  provenance-aware creation, and exact cleanup verification.
- `build_peirates_for_kind_node` rather than a host-architecture build.

Configure the disposable kubelet explicitly:

```yaml
kubeadmConfigPatches:
- |
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  enableDebuggingHandlers: true
  enableSystemLogHandler: true
  enableSystemLogQuery: false
```

Disabling query mode makes the test exercise the legacy `/logs/<path>` file
server directly. This configuration exists only inside the disposable Kind
node.

Create these fixtures:

- A synthetic marker at `/tmp/peirates-hostlog-marker` inside the Kind node.
  Record its content, hash, mode, UID/GID, device, and inode.
- A positive pod running as UID 0 with `allowPrivilegeEscalation: false`, all
  capabilities dropped, and node `/var/log` mounted read-write at
  container `/var/log`. This same-path fixture exercises the narrow fallback
  for runtime-staged mounts whose mountinfo root no longer records `/var/log`.
- A negative pod with the same mount marked `readOnly: true`.
- A positive service account with only the required `get` access to
  `nodes/proxy` for the action. If node enumeration is added, grant only the
  exact additional node verbs and document why.
- A denied service account with no `nodes/proxy` permission.
- Downward-API `NODE_NAME` values for the action pods.

Use operator credentials to copy the binary and invoke the pods; neither test
service account needs `pods/exec`. Prove with impersonated authorization checks
that the positive account has the intended proxy permission and cannot read
Secrets or create workloads.

Before running Peirates, independently prove:

- The pod mount and node `/var/log` have matching filesystem identity.
- A test-owned file can be created and removed through the writable fixture.
- The same operation fails through the read-only fixture.
- The API-server proxy `/logs/` route responds with operator credentials.
- `/var/log/tmp/peirates-hostlog-marker` does not exist, so a successful read
  cannot be explained by ordinary path containment.

Exercise numeric, canonical, and alias dispatch with complete line-oriented
input. Each invocation reads only the synthetic marker and is followed by
independent assertions that:

- Returned content exactly matches the marker.
- Marker hash, metadata, device, and inode are unchanged.
- The exact temporary link reported by Peirates is absent as both an ordinary
  path and a dangling symlink.
- No `.peirates-hostlog-*` entry remains anywhere below node `/var/log`.
- The runner pod remains Ready and kubelet/API health checks pass.
- Kubernetes object snapshots are unchanged except for expected test setup.

Also prove that a nonexistent target cleans up, the denied service account
fails before mutation, and the read-only pod fails before network access or
mutation. Keep timeout, oversize, redirect, collision, malformed-target, and
cancellation cases in deterministic Go unit tests rather than creating more
live clusters.

Extend the existing scanner Kind test with writable and read-only `/var/log`
fixtures. Keep `automountServiceAccountToken: false` for scanner-only pods and
assert that the scanner neither emits marker content nor creates a Peirates
symlink. Compare only test-owned names or the Peirates prefix because legitimate
files under `/var/log` change continuously.

The Kind integration owner must update these files together:

- `Makefile`: add the new case record and target recipe.
- `.github/workflows/kind.yaml`: add the target and cluster environment in the
  same order.
- `test/kind-aggregate-test.sh`: update 19-entry assertions, comments, and
  success output to 20.
- `test/kind-cluster-ownership-test.sh`: include the new hardened script in all
  mocked ownership scenarios.
- `test/README.md`: document configuration, RBAC, isolation, negative controls,
  and cleanup.

Validate but do not plan changes to `test/run-kind-tests.sh` or
`test/kind-build-helpers.sh` unless the new test exposes a real deficiency.
Do not copy the older boolean-only `cluster_owned=true` lifecycle still present
in some scripts.

## Agent execution plan

The coordinator owns the contract, sequencing, integration review, and final
validation. Agents must not modify files outside their assigned ownership
without handing the file back to the coordinator and waiting for reassignment.

### Gate 0: coordinator contract and baseline

Before implementation, the coordinator:

1. Obtains approval for this plan, command names, menu item 33, response limits,
   initial API-proxy-only transport, and deferred scope.
2. Records `git status --short` and preserves every unrelated change.
3. Runs the current safe baseline: `make test-quiet`, `go vet ./...`, and
   `make build`.
4. Records the current Kind inventory without starting a cluster.
5. Freezes the shared `HostLogMount`, `Fetcher`, `Options`, raw-transport, and
   output contracts before parallel edits.

### Wave 1: two agents in parallel

**Agent A — host-log filesystem primitive** owns:

- `internal/modules/escapeutil/mountinfo.go`
- `internal/modules/escapeutil/mountinfo_test.go`
- New `internal/modules/hostlog/*`

Agent A implements mount qualification, target validation, directory-descriptor
operations, symlink ownership, injected fetcher behavior, cleanup, Linux tests,
and unsupported-platform stubs. Agent A does not edit scanner, Kubernetes,
application, UI, documentation, or Kind files.

**Agent B — bounded Kubernetes transport** owns:

- New `internal/kube/raw.go`
- New `internal/kube/raw_test.go`
- The smallest necessary edits to `internal/kube/kubectl.go` or
  `internal/kube/client.go` for a subresource-aware authorization seam

Agent B implements authenticated bounded raw responses and exact
subresource-aware authorization. Agent B does not edit module, application,
UI, documentation, or Kind files and adds no dependency unless the coordinator
approves it.

The coordinator reviews and integrates both results, reopens every changed file
in the primary worktree, verifies no ownership overlap, and runs focused tests
before Wave 2.

### Wave 2: two agents in parallel

**Agent C — scanner integration** owns:

- `internal/modules/containerescape/containerescape.go`
- `internal/modules/containerescape/containerescape_test.go`
- `internal/modules/containerescape/scanner_linux.go`
- `internal/modules/containerescape/scanner_linux_test.go`
- `internal/modules/containerescape/scanner_unsupported.go` if required

Agent C adds the seventh deterministic finding using Agent A's helper. Agent C
does not edit `escapeutil`, `hostlog`, Kubernetes, app, UI, docs, or Kind files.

**Agent D — app, UI, and command documentation** owns:

- `internal/app/container_escape_modules.go`
- `internal/app/container_escape_modules_test.go`
- `internal/app/module_registry.go`
- `internal/app/dispatch.go`
- `internal/app/menu.go`
- `internal/app/module_commands_test.go`
- `internal/ui/menu.go`
- `internal/ui/completion.go`
- `internal/ui/completion_test.go`
- `docs/commands/hostlog-symlink-read.md`
- `docs/commands/container-escape-scan.md`
- `docs/commands/README.md`
- `docs/commands/manifest.tsv`

Agent D wires the stable Wave 1 APIs to the active session and owns every shared
command registry so no other agent edits those files concurrently. Agent D does
not edit the core modules, Kubernetes transport, or Kind infrastructure.

The coordinator again reviews the primary worktree, reconciles only deliberate
cross-package contract changes, and runs focused and full safe tests before
Wave 3.

### Wave 3: one serial integration owner

**Agent E — Kind integration and shared test inventory** owns:

- `test/container-escape-scan-kind-integration.sh`
- New `test/hostlog-read-kind-integration.sh`
- `Makefile`
- `.github/workflows/kind.yaml`
- `test/kind-aggregate-test.sh`
- `test/kind-cluster-ownership-test.sh`
- `test/README.md`

Agent E starts only after scanner output and action prompts are stable. This
agent is the sole editor of shared Kind infrastructure, updates parity from
19/19/19 to 20/20/20, runs safe shell/ownership/aggregate checks, and then runs
the focused live targets only after the coordinator verifies Docker and Kind
readiness.

### Gate 4: coordinator final verification

The coordinator:

1. Re-reads representative files and checks all expected paths in the primary
   worktree rather than relying on agent completion messages.
2. Reviews the complete diff for scope, secrets, unintended behavior changes,
   temporary files, and generated artifacts.
3. Runs the validation matrix below serially where builds share `/tmp` caches.
4. Confirms that no Peirates symlink, disposable Kind cluster, test pod, or
   synthetic marker remains.
5. Reports actual evidence and limitations. Remote CI or a runtime/version
   matrix is not claimed unless it was actually run.
6. Stages explicit reviewed paths only if the maintainer separately requests a
   commit.

## Validation matrix

Focused package checks:

```sh
go test ./internal/modules/escapeutil ./internal/modules/hostlog
go test ./internal/kube
go test ./internal/modules/containerescape
go test ./internal/app ./internal/ui
```

Safe repository checks:

```sh
go fmt ./...
go test -race ./internal/modules/... ./internal/kube ./internal/app ./internal/ui
go vet ./...
make test-quiet
GOFLAGS=-p=1 make build
git diff --check
```

Shell and inventory checks:

```sh
bash -n test/container-escape-scan-kind-integration.sh \
  test/hostlog-read-kind-integration.sh \
  test/run-kind-tests.sh \
  test/kind-aggregate-test.sh \
  test/kind-cluster-ownership-test.sh
make kind-aggregate-test
make kind-cluster-ownership-test
make -n kind-tests
make -s kind-test-inventory
```

Before any live target:

```sh
id
docker info
kind get clusters
```

Focused live gates:

```sh
make container-escape-scan-kind-test
make hostlog-read-kind-test
kind get clusters
```

Run `make kind-tests` only after the focused targets pass and the coordinator
confirms sufficient time and disk space. Inspect the static `peirates` artifact
with `file` and `ldd`; the expected `ldd` result is “not a dynamic executable”
or its platform equivalent. Remove only disposable artifacts created by the
implementation run.

## First-release acceptance criteria

- Existing commands, aliases, flags, output routes, build artifacts, and menu
  behavior remain compatible.
- `container-escape-scan` performs no mutation and emits exactly one stable new
  finding.
- `/var/log` and true descendants are detected without accepting similar path
  prefixes.
- The action refuses read-only, ambiguous, missing, changed, or symlinked mount
  candidates before mutation.
- The action accepts only one normalized absolute non-root target.
- Authorization and endpoint probes occur before symlink creation.
- Every handled exit path removes only the exact Peirates-created symlink.
- Target content and metadata are never modified.
- Network responses and errors are bounded, redirects are rejected, TLS honors
  the active session, and credentials are never logged.
- Failures distinguish local mount, RBAC, endpoint, TLS, timeout, response-size,
  target, and cleanup problems.
- Linux and unsupported-platform builds compile and have stable tests.
- Numeric, canonical, and alias command forms dispatch identically.
- Documentation and command manifests describe actual behavior and side
  effects.
- The Kind test reaches only its disposable node-container boundary, uses no
  workstation/CI host mount, proves external state, and verifies exact cluster
  cleanup.
- Makefile, executable scripts, aggregate assertions, ownership regressions,
  and CI matrix have exact 20-entry parity after the new target is added.

## Follow-on decision gates

After the first release passes its live gate, create separate plans for any of
these additions:

1. Direct kubelet transport with explicit endpoint selection, verified TLS by
   default, and a separately explicit insecure mode.
2. CRI `0.log` replacement through `pods/log`, with runtime/version matrices,
   atomic restoration, and proof that ordinary logging continues.
3. Refactoring `gatherPodCredentials` behind a filesystem-reader interface.
   Keep the local backend attached to startup and `nodefs-steal-secrets`; expose
   a host-log backend only through an explicit operator command.
4. Cluster-side risk classification in `find-volume-mounts`, preserving its
   existing output while adding container mount path, node, and effective
   read-only state.
5. Log tamper, disk-pressure, collector confused-deputy, or runtime reopen/write
   experiments, each with an independent destructive-action safety contract.
