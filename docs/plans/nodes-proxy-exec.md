# Nodes/proxy WebSocket execution implementation plan

Status: **IMPLEMENTED AND LIVE-VALIDATED.** The maintainer approved this plan
and explicitly requested parallel agent implementation on 2026-09-21. The
implementation preserves the contract below and passed its disposable Kind
proof on the same date; amend the plan before expanding scope.

Revision note: the plan now requires checking every service-account token in
Peirates' `Session.ServiceAccounts` snapshot for node-specific
`get nodes/proxy` permission, then explicitly selecting a qualifying token.
The scan must not stop at the active or first successful token.

On 2026-09-22 the maintainer amended the approved interaction: `insecure` is
the displayed TLS default and takes effect immediately when selected, without
a second acknowledgement. The execution warning and node-specific final
confirmation were also removed. Verified `ca-data` and `ca-file` modes and the
verified-TLS Kind gate remain in scope.

The maintainer also replaced JSON argv input with a plain command line. Peirates
parses quoting and escaping locally and constructs the argv array; it does not
invoke a shell or perform expansion.

## Goal

Add a bounded Peirates capability that demonstrates and uses the command-
execution authority carried by Kubernetes `get` permission on the
`nodes/proxy` subresource. The first release will:

1. Check every service-account token currently stored in Peirates for
   node-specific `get nodes/proxy` access.
2. Let the operator explicitly select one qualifying stored token.
3. Connect directly to one explicitly selected kubelet HTTPS endpoint using
   that token.
4. Enumerate running containers from that kubelet's `/pods` endpoint.
5. Execute one operator-selected, non-interactive command in one selected
   container through a WebSocket HTTP `GET` request.
6. Distinguish confirmed GET-only execution from permission-only or ordinary
   broad `nodes/proxy` access.
7. Prove multi-token discovery, execution, and negative controls in a
   disposable Kind cluster.

The behavior is powerful but is not assigned a CVE. The Kubernetes project
documents that WebSocket requests use HTTP `GET`, that `get nodes/proxy` is not
read-only, and that direct kubelet access can execute commands while bypassing
API-server admission control and ordinary Kubernetes audit logging.

Primary references:

- [Graham Helton: Kubernetes Remote Code Execution Via Nodes/Proxy GET Permission](https://grahamhelton.com/blog/nodes-proxy-rce)
- [Kubernetes kubelet authentication and authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes)
- [Kubernetes API-server bypass risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/#the-kubelet-api)
- [KEP-2862: Fine-grained kubelet authorization](https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/2862-fine-grained-kubelet-authz)

## Proposed first-release contract

The following values are proposed and must be frozen at approval:

| Item | Proposed value |
|---|---|
| Menu item | `34` |
| Canonical command | `nodes-proxy-exec` |
| Aliases | None |
| Menu text | Execute one command through direct kubelet WebSocket access |
| Default proof command | `id` |
| Kubelet HTTPS port | Explicit origin, normally `10250` |
| Pod-list response limit | 8 MiB |
| Combined command-output limit | 1 MiB |
| Error-detail limit | 4 KiB |
| Read-only request timeout | 10 seconds |
| Command timeout | 30 seconds |
| Initial execution scope | One node, one running container, one command |
| Stored-token scope | Every entry in `Session.ServiceAccounts` at module start |
| Access-review concurrency | At most 4 stored tokens concurrently |
| Credential selection | Explicit; never auto-select a token |

Menu item 34 is the next unassigned value after the implemented item 33. The
new feature must not change the behavior or aliases of menu item 22,
`exec-via-kubelet`.

The action uses this line-oriented flow:

1. A Kubernetes node name. Offer `NODE_NAME` as a default when present.
2. Review every currently stored service-account token against that node.
3. An explicit numbered choice from the tokens allowed to `get nodes/proxy`.
4. A direct kubelet HTTPS origin, such as `https://10.0.0.12:10250`.
5. A numbered running-container target obtained from the selected kubelet.
6. A plain command line, defaulting to `id`, which Peirates parses into argv.

The command-line parser preserves argument boundaries using whitespace, single
quotes, double quotes, and backslash escaping. Peirates must not invoke a shell,
perform variable or glob expansion, or implicitly prepend `/bin/sh -c`. An
operator who needs shell evaluation can explicitly enter a command such as
`/bin/sh -c "printf ready"`.

Direct `peirates -m nodes-proxy-exec` invocation uses the same prompts and
validation. Execution starts after the command argv is accepted and the target
is freshly revalidated, without an additional warning or confirmation prompt.

## Why this is a separate command

The existing `exec-via-kubelet` implementation is a different attack path. It:

- requires API permission to retrieve Node objects;
- enumerates pods through the legacy anonymous kubelet port 10255;
- executes through an HTTP `POST` to `/run`;
- does not authenticate that request with the active service-account token;
- unconditionally disables kubelet TLS verification; and
- automatically attempts token reads across discovered containers.

Changing item 22 to use the new behavior would alter existing CLI semantics
and obscure whether a result proved GET-only WebSocket execution. The first
release therefore adds a new command. Refactoring or deprecating item 22, if
desired, requires a separate compatibility plan.

## Threat model and required conditions

The feature is usable only when all of these conditions hold:

- At least one token in the module-start snapshot of
  `Session.ServiceAccounts` authenticates to the current Kubernetes API server
  and is authorized for `get` on `nodes/proxy` for the selected node.
- The explicitly selected qualifying token also authenticates to the kubelet.
- The Peirates process has direct network reachability to the kubelet HTTPS
  endpoint, normally TCP 10250.
- The selected pod and container are running on that kubelet.
- The kubelet and container runtime negotiate a supported remote-command
  WebSocket protocol.

`KubeletFineGrainedAuthz` does not remove the risk. Fine-grained authorization
provides narrower permissions for read-oriented endpoints, but `/exec` remains
under the `nodes/proxy` fallback. The live gate must nevertheless report the
tested Kubernetes version and must not claim universal provider or version
behavior.

Permission, reachability, authentication, container enumeration, and command
execution are separate facts. A positive access review or reachable port is
not proof of code execution.

## Scope boundaries

The first release includes:

- A snapshot and node-specific access review of every token currently stored
  in `Session.ServiceAccounts`, including tokens that are not the active
  Peirates identity.
- A `get nodes/proxy` SelfSubjectAccessReview for every stored token and a
  `create nodes/proxy` negative-control review for each GET-qualified token.
- Explicit selection of one qualifying token without changing the session's
  active identity or stored-token order.
- Bearer-token authentication for the selected stored token.
- Direct kubelet `/pods` retrieval using the same selected credential and TLS
  settings as the execution request.
- Normal, init, and ephemeral containers whose status is currently running.
- WebSocket remote-command protocols v5 through v1, in preference order.
- Exact stdout, stderr, structured exit status, and negotiated-protocol
  reporting.
- Context cancellation, response limits, execution timeout, and explicit TLS
  controls.
- Unit, command-contract, safe shell, and disposable Kind coverage.
- Command documentation and security implications.

The first release does not include:

- Interactive TTY or shell relay.
- Stdin forwarding or terminal resizing.
- Automatic execution in every pod, container, or node.
- Automatic selection or prioritization of privileged or control-plane pods.
- Automatic selection of the first token with sufficient access.
- Mutation, reordering, removal, or refresh of Peirates' stored tokens.
- Client-certificate execution; it does not satisfy the requested stored-token
  review and can be added later as a separately labeled credential type.
- Automatic token, secret, or filesystem harvesting.
- Reverse shells, persistence, host escape payloads, port forwarding, attach,
  or kubelet `/run` support.
- API-server `nodes/<name>/proxy` transport as an execution fallback.
- HTTP POST or SPDY fallback.
- Node-port scanning, default-gateway inference, DNS guessing, or automatic
  expansion from one node to the cluster.
- Automatic retry with disabled TLS verification.
- Changes to the existing `exec-via-kubelet` behavior.

Batch execution, interactive shells, and automated privilege-target ranking
require separate review after the bounded primitive passes its live gate.

## Result classification

Each stored token receives one access-review state: `allowed`, `denied`,
`error`, or `unchecked`. These per-token states are separate from the module's
single final execution conclusion:

| Classification | Required evidence |
|---|---|
| `confirmed-get-only-exec` | `get nodes/proxy` allowed, `create nodes/proxy` denied, direct authenticated WebSocket execution succeeded |
| `broad-proxy-access` | `get` and `create` allowed and direct execution succeeded; GET-only distinction was not isolated |
| `execution-confirmed-authz-unchecked` | Access review was explicitly disabled, but direct authenticated execution succeeded |
| `permission-candidate` | `get nodes/proxy` allowed, but direct execution was not proven |
| `not-exploitable-from-here` | Authorization denied, endpoint unreachable, authentication failed, target invalid, or WebSocket execution denied |

An access-review failure for one token must not prevent review of the remaining
stored tokens. If no token is allowed, stop before direct kubelet access and
summarize denied and error counts. When reviews are explicitly disabled, mark
every token `unchecked`, require explicit token selection, and use only the
`execution-confirmed-authz-unchecked` classification after actual execution.
Never translate an access-review error into an allowed result.

## Package and dependency design

### Capability package

Create `internal/modules/nodesproxyexec`. It must not import `internal/app`.
It owns validation, preflight sequencing, target selection data, classification,
and bounded execution orchestration behind injected interfaces.

The package contract should express these concepts; exact Go names can change
at implementation review without changing behavior:

```go
type Target struct {
	NodeName      string
	Namespace     string
	PodName       string
	ContainerName string
}

type CredentialRef struct {
	Index           int
	Name            string
	DiscoveryMethod string
	Kind            string
}

type CredentialAccess struct {
	Credential  CredentialRef
	GetProxy    AccessState
	CreateProxy AccessState
}

type Options struct {
	Credential     CredentialRef
	Target         Target
	Argv           []string
	CommandTimeout time.Duration
	OutputLimit    int64
}

type ProbeResult struct {
	Credentials []CredentialAccess
	Containers  []Target
}

type ExecResult struct {
	Stdout            []byte
	Stderr            []byte
	ExitCode          int
	Protocol          string
	Classification    string
}

type Kubelet interface {
	Probe(context.Context, string) error
	ListRunningContainers(context.Context) ([]Target, error)
	Exec(context.Context, Target, []string, io.Writer, io.Writer) (ExecStatus, error)
}
```

`CredentialRef` is display metadata and an opaque lookup key; it must never
contain a token or token digest. The application keeps
the corresponding connection copies private. The module must accept its
authorization and network collaborators through interfaces so multi-token
permission combinations, partial failures, cancellation, and output overflow
are deterministic unit tests.

### Direct kubelet transport

Add a direct kubelet client under `internal/kube`, separate from the existing
API-server raw request transport. It owns:

- strict kubelet-origin parsing;
- kubelet-specific TLS construction;
- selected-token bearer authentication;
- bounded `/pods` retrieval and decoding; and
- WebSocket remote-command negotiation and stream handling.

Use `k8s.io/client-go/tools/remotecommand.NewWebSocketExecutorForProtocols`
rather than implementing channel framing locally. Importing client-go directly
will promote an already-transitive Kubernetes dependency; it must not introduce
a second WebSocket stack.

Use HTTP `GET` only and request remote-command protocols in this order:

1. `v5.channel.k8s.io`
2. `v4.channel.k8s.io`
3. `v3.channel.k8s.io`
4. `v2.channel.k8s.io`
5. `channel.k8s.io`

Do not use a fallback executor that retries with POST or SPDY. A POST success
would test `create nodes/proxy`, not the proposed GET-only capability.

### Kubernetes access review

Extend `internal/kube.ResourceAttributes` with:

```go
Name string `json:"name,omitempty"`
```

The preflight reviews cluster-scoped attributes with empty API group and
namespace:

```text
verb=get,    resource=nodes, subresource=proxy, name=<selected-node>
verb=create, resource=nodes, subresource=proxy, name=<selected-node>
```

Including the resource name is required to handle Roles that constrain
`nodes/proxy` with `resourceNames`. Unit tests must verify that the field is
serialized and that existing callers remain unchanged when it is empty.

### Application orchestration

Add `internal/app/nodes_proxy_exec.go` for prompts, signal-aware context setup,
and rendering. It creates the internal/kube client
and passes only the required interfaces into the capability package. The
registry handler must pass both `session.Connection` and a value snapshot of
`session.ServiceAccounts`; the module must not operate through a pointer to the
live slice.

Wire the command through:

- `internal/app/module_registry.go`
- `internal/app/dispatch.go`
- `internal/app/menu.go`
- `internal/ui/menu.go`
- `internal/ui/completion.go`
- the command-surface regression tests

The entry point in `cmd/peirates` remains unchanged.

## Stored-token access review

The module takes a snapshot of `Session.ServiceAccounts` when invoked. Tokens
found or removed later in the Peirates session do not alter an in-progress
scan. Preserve the original slice order for display and selection.

For each stored entry:

1. Copy the current API-server connection settings.
2. Set the candidate token and token name on the copy.
3. Clear client-certificate identity fields on the copy.
4. Submit a node-specific `get nodes/proxy` SelfSubjectAccessReview.
5. If GET is allowed, also submit the `create nodes/proxy` negative-control
   review.
6. Store only the entry's original index, sanitized name, sanitized discovery
   method, and access states in the result.

The scan uses at most four workers and renders results in original stored-token
order after all workers finish. Cancellation stops pending work. A timeout,
401, 403, malformed token, or API error applies only to that token unless the
parent context is canceled.

Identical token strings may be reviewed once and have the result applied to
each matching stored entry. Deduplication may use a full SHA-256 digest only as
an in-memory map key. Never print, persist, truncate for display, or return a
token digest as an identifier.

Display a table similar to:

```text
Stored token RBAC results for node worker-1:
[0] default:runner        get nodes/proxy=denied
[1] monitoring:collector get nodes/proxy=allowed create nodes/proxy=denied
[2] old:agent             get nodes/proxy=error (authentication failed)
```

Names and discovery methods are untrusted display text and must have terminal
control characters removed. Do not print raw JWT subjects, payloads, token
prefixes, hashes, or API error bodies that contain credentials.

After the table, accept only the original index of an allowed stored token.
Never auto-select a token, even when exactly one is allowed. A denied, error,
unchecked, missing, or out-of-range index is rejected without direct kubelet
access. When authorization checks were explicitly disabled, accept an
unchecked token only after a second warning that RBAC qualification is
unproven.

The selected token uses a private `ServerInfo` copy. Selection must not
call `AssignServiceAccount` on `session.Connection`, reorder the stored slice,
or change the identity shown by later Peirates menus. All subsequent node
lookup, `/pods`, and `/exec` requests in this invocation use the selected copy.

If no service-account tokens are stored, report that fact and stop before
direct kubelet access. Do not claim a token permission result or silently fall
back to the active connection's client certificate.

## Endpoint and node selection

The operator must select a node name and a kubelet origin independently.

Node-name behavior:

- Offer trimmed `NODE_NAME` as a default.
- Validate it as a Kubernetes DNS subdomain.
- Do not use the pod hostname as proof of node identity.
- Use it in node-specific access reviews and target validation.

Origin behavior:

- Require `https` and an explicit host and port.
- Accept only an origin: no userinfo, path other than empty or `/`, raw query,
  or fragment.
- Normalize IPv6 brackets and reject ambiguous host syntax.
- Reject redirects so bearer credentials cannot move to another origin.
- Do not honor an origin embedded in untrusted pod metadata.
- Do not infer an IP from the default gateway or scan port 10250.

As an optional convenience, when the selected stored token can `get` the
selected Node object, Peirates may offer that object's `InternalIP` as the origin
default. It must show the resolved value and still require explicit operator
input. A
manual origin remains available when Node-object access is denied. Automatic
cluster-wide Node listing is outside the first release.

## Authentication and TLS

Use the explicitly selected stored-token connection copy without printing or
placing credentials in a URL:

- Send `Authorization: Bearer <token>` for the selected stored token.
- Do not write credentials to temporary files.

Kubelet TLS settings are separate from the API-server connection because the
two endpoints can use different certificate authorities and names. Define a
narrow kubelet TLS options type with CA data, CA file, optional server name,
and an explicit insecure boolean.

Defaults:

- Display `insecure` as the default TLS mode and apply it immediately when the
  operator selects it or presses Enter.
- Keep the active connection's CA data and CA path available through explicit
  `ca-data` and `ca-file` choices, but do not assume either validates the
  kubelet serving certificate.
- Do not inherit `ServerInfo.IgnoreTLS` silently.
- Do not retry insecurely after a verification failure.
- Permit insecure kubelet TLS when the operator selects it or accepts it as the
  displayed default, with no second warning or acknowledgement prompt. Keep a
  narrowly annotated gosec exception at TLS construction.
- Require TLS 1.2 or newer.

The transport must not log tokens, certificate material, request headers, or
unbounded server responses.

## Pod enumeration and target validation

Retrieve `/pods` directly from the chosen kubelet after access review and TLS
preflight. Decode it as a Kubernetes `corev1.PodList` and retain only statuses
that are currently running.

For each candidate display:

- namespace;
- pod name;
- container name;
- container kind: regular, init, or ephemeral; and
- node name from the pod spec.

Do not display environment variables, volume contents, annotations, service-
account tokens, or container command lines. Sort candidates deterministically
by namespace, pod, container kind, and container name. Do not auto-select even
when exactly one candidate exists.

Before execution, require that:

- the selected tuple still appears as running in a fresh `/pods` response;
- its `spec.nodeName` equals the selected node;
- every path component is non-empty and contains no slash or NUL; and
- argv is non-empty, within a documented argument-count and aggregate-size
  limit, and contains no NUL.

URL construction must use structured `url.URL` and `url.Values`. Add every
argv element as a separate `command` query value. Do not concatenate raw path
or query strings.

## WebSocket execution and bounds

Construct the direct kubelet route:

```text
/exec/<namespace>/<pod>/<container>
```

Set query fields from the actual stream configuration:

```text
input=0
output=1
error=1
tty=0
command=<one repeated value per argv element>
```

Execution rules:

- No stdin and no TTY in the first release.
- Use a context covering handshake, execution, stream draining, and close.
- Apply the 30-second default timeout when execution begins.
- Bound stdout and stderr to 1 MiB combined. Reaching the limit cancels the
  context, closes the WebSocket, and returns a stable truncation error.
- Preserve stdout and stderr separately within the combined budget.
- Decode the structured remote-command error channel and report the actual
  exit code when available.
- Treat successful WebSocket upgrade without a completed command status as an
  indeterminate failure, not confirmed execution.
- Close all response bodies, idle connections, and WebSocket sessions.
- Never automatically rerun a failed command.

The default `id` command is a minimally persistent proof but still creates a
process in another container. Open the execution WebSocket immediately after
the operator's argv is accepted and the target is revalidated.

## Operator output

Before execution, print a preflight summary similar to:

```text
Node: worker-1
Stored tokens reviewed: 3 (allowed=1 denied=1 error=1)
Selected token: [1] monitoring:collector
Kubelet: https://10.0.0.12:10250
get nodes/proxy: allowed
create nodes/proxy: denied
Kubelet TLS: verified
Direct /pods: authorized; 8 running containers found
Target: kube-system/example/example
Argv: ["id"]
```

The execution starts immediately after this summary, without a separate
warning or confirmation prompt.

After execution, report:

- negotiated WebSocket protocol;
- exit code or bounded transport error;
- separate stdout and stderr sections;
- the exact result classification; and
- a reminder that container execution does not by itself prove node or
  physical-host compromise.

Sanitize terminal control characters in summaries and error details. Preserve
command output bytes except for the documented output bound; do not include
command output in a one-line classification message.

## Unit and regression tests

### `internal/kube`

Add tests for:

- strict HTTPS origin parsing, including IPv4, bracketed IPv6, and DNS names;
- rejection of credentials, unexpected paths, queries, fragments, redirects,
  and non-HTTPS schemes;
- selected stored-token bearer authentication;
- verified CA data, verified CA file, server-name override, missing CA,
  malformed certificates, and explicit insecure TLS;
- `/pods` response, error-body, and timeout bounds;
- v5 and v4 WebSocket negotiation;
- repeated command parameters and path-component encoding;
- stdout/stderr separation and structured non-zero exits;
- output overflow cancellation and context cancellation; and
- proof that no POST or SPDY fallback occurs.

Use local TLS and WebSocket test servers. Tests must inspect method, path,
query, subprotocols, authorization header, close behavior, and secret
redaction without sending credentials externally.

### `internal/modules/nodesproxyexec`

Use fake access-review and kubelet interfaces to cover:

- every stored token is reviewed, including entries after the active token and
  after the first allowed token;
- mixed GET-allowed, GET-denied, CREATE-allowed, error, and unchecked results;
- stable original-index ordering despite bounded concurrent reviews;
- duplicate token values are reviewed once but retain each stored label;
- one token's access-review error does not stop remaining reviews;
- cancellation stops pending reviews;
- token metadata is sanitized and token values and digests never enter result
  objects or errors;
- only an explicitly selected GET-allowed token reaches direct kubelet access;
- denied, error, unchecked, missing, and out-of-range selections fail closed;
- selection does not mutate the live connection or stored-token slice;
- no qualifying token stops before direct kubelet access;
- reachability, authentication, listing, and execution failures as distinct
  evidence;
- deterministic target sorting and explicit selection;
- target disappearance or node mismatch during the fresh re-probe;
- empty, oversized, malformed, or NUL-containing argv;
- timeout, output overflow, non-zero exit, and successful execution; and
- every result classification.

### `internal/app` and command surface

Add tests for:

- menu number, canonical command, registry, alias map, completion, and both
  menu renderers;
- `-m nodes-proxy-exec` dispatch;
- line-oriented prompts preserving subsequent input;
- passing all stored session tokens from the registry without changing the
  active session identity;
- default `NODE_NAME`, stable per-token RBAC table, explicit token selection,
  explicit origin, target choice, and plain command input;
- no stored tokens, one qualifying token, multiple qualifying tokens, and a
  qualifying non-active token;
- EOF at any required input exiting without execution;
- command errors returning control to the menu; and
- secrets never appearing in rendered errors.

Update the existing exhaustive command lists rather than adding a separate,
weaker registration test.

## Disposable Kind integration test

Add `test/nodes-proxy-exec-kind-integration.sh`. The script must document its
purpose, tested behaviors, prerequisites, security impact, and each code
section following the repository's shell-test convention.

The fixture creates:

- one disposable Kind cluster using the repository-pinned node image;
- an attacker service account granted only `get` on `nodes/proxy`;
- a runner service account and another stored service account without
  `nodes/proxy`;
- controller-populated token Secrets for the attacker and stored denied
  accounts;
- a runner pod using the denied runner identity, containing the Peirates
  binary, its projected CA, and deterministic synthetic kubelet credential
  directories from which Peirates stores the alternate tokens;
- one target pod on the selected node; and
- a unique marker path inside the target container.

Before Peirates runs, independently assert with administrator credentials:

```text
attacker can get nodes/proxy
attacker cannot create nodes/proxy
attacker cannot create pods/exec
runner identity cannot get nodes/proxy
stored denied identity cannot get nodes/proxy
```

The runner's active token must be denied. The positive result must come from
the non-active attacker token discovered in Peirates' stored-token list. This
proves the feature checks beyond the current identity rather than succeeding
only because the initial connection is privileged.

The positive action executes exact argv equivalent to:

```text
["/bin/sh","-c","printf '%s' '<unique-marker>' > /tmp/<unique-path>"]
```

The test then uses administrator `kubectl exec` to verify the exact marker in
the target container. This independent assertion proves that menu output alone
did not create a false positive.

Negative controls must prove:

- all stored identities appear in the RBAC result table in deterministic
  order;
- the denied active identity and stored denied identity cannot be selected for
  direct kubelet access;
- scanning continues through denied entries and does not stop after finding
  the allowed attacker token;
- invalid command syntax creates no marker;
- a nonexistent or non-running target creates no marker;
- the attacker still lacks `create nodes/proxy` and `create pods/exec` after
  successful execution; and
- no service-account token or token digest appears in captured output.

The positive fixture should validate kubelet TLS with a trusted CA and matching
name or IP. If the repository-pinned Kind image cannot provide a verifiable
kubelet serving certificate for its reachable address, stop and document that
fixture gap rather than making insecure TLS the only positive gate. A separate
explicit-insecure case may be added only in addition to the verified path.

Cleanup must use the existing claim-aware, fail-closed Kind helpers and verify
that the exact disposable cluster is absent. No pre-existing cluster may be
deleted.

Register `nodes-proxy-exec-kind-test` in exact parity across:

- `Makefile` `KIND_TEST_CASES` and target recipe;
- `.github/workflows/kind.yaml`; and
- `test/kind-aggregate-test.sh` inventory expectations.

The current 20/20/20 inventory becomes 21/21/21. Shared Kind infrastructure
changes must be made serially to avoid conflicting edits.

## Documentation

Add `docs/commands/nodes-proxy-exec.md` from the command template and update
`docs/commands/manifest.tsv` plus any generated or checked command indexes.

The command documentation must explain:

- that every token already stored in the current Peirates session is reviewed
  against the selected node before credential selection;
- that the scan uses the current API-server origin and trust settings and does
  not discover or try other clusters for stored tokens;
- per-token result meanings and the fact that tokens and digests are never
  displayed;
- the direct-kubelet network requirement;
- the difference between API-server proxying and direct kubelet access;
- that `get nodes/proxy` is not read-only;
- required authentication and TLS inputs;
- exact first-release bounds and exclusions;
- why successful container execution is not automatically node compromise;
- the API-server admission and audit visibility gap; and
- defensive guidance: remove `nodes/proxy` where possible, use fine-grained
  kubelet permissions, and restrict network access to port 10250.

Do not describe the feature as a CVE or imply that every cluster is reachable
or exploitable.

## Planned file ownership

Expected new files:

- `internal/modules/nodesproxyexec/nodesproxyexec.go`
- `internal/modules/nodesproxyexec/nodesproxyexec_test.go`
- `internal/kube/kubelet_websocket.go`
- `internal/kube/kubelet_websocket_test.go`
- `internal/app/nodes_proxy_exec.go`
- `internal/app/nodes_proxy_exec_test.go`
- `test/nodes-proxy-exec-kind-integration.sh`
- `docs/commands/nodes-proxy-exec.md`

Expected existing-file edits:

- `go.mod` and `go.sum` only as produced by the direct client-go import and
  `go mod tidy`
- `internal/kube/kubectl.go`
- `internal/kube/raw_test.go` or a focused access-review test file
- `internal/app/module_registry.go`
- `internal/app/dispatch.go`
- `internal/app/menu.go`
- `internal/ui/menu.go`
- `internal/ui/completion.go`
- `internal/app/module_commands_test.go`
- `docs/commands/manifest.tsv`
- `Makefile`
- `.github/workflows/kind.yaml`
- `test/kind-aggregate-test.sh`

Avoid unrelated changes to the existing kubelet, hostlog, raw API, and exec-
via-API implementations. If implementation reveals a necessary shared
refactor, stop at that boundary and amend this plan before proceeding.

## Implementation sequence and gates

### Gate 0: contract approval

The maintainer approves or edits:

- command name, menu number, and lack of aliases;
- exact one-node/one-target/one-command scope;
- mandatory review of every module-start stored token, four-worker limit,
  stable output order, and explicit qualifying-token selection;
- treatment of duplicate tokens, per-token errors, disabled access reviews,
  and the no-stored-token case;
- plain command input, quote-aware argv construction, and default `id` command;
- immediate execution after command submission;
- endpoint and kubelet-specific TLS behavior;
- time and byte limits;
- result classifications; and
- the verified-TLS Kind requirement.

No implementation starts before this gate.

### Phase 1: access-review and direct transport primitives

1. Add node-name support to `ResourceAttributes` with regression tests.
2. Add strict origin and kubelet TLS construction.
3. Add bounded authenticated `/pods` retrieval.
4. Add GET-only WebSocket remote command with protocol and output handling.
5. Run focused `internal/kube` tests and `go mod tidy` checks.

Gate: transport unit tests pass, no credential appears in errors, and no POST
fallback exists.

### Phase 2: capability engine

1. Add the bounded stored-token access-review engine and immutable credential
   references.
2. Add explicit credential selection without mutating session state.
3. Add the injected kubelet preflight and execution engine.
4. Add deterministic container enumeration and revalidation.
5. Add all classifications and bounded result handling.
6. Run focused capability tests and race tests.

Gate: every stored token is accounted for, token material is absent from
results, session state remains unchanged, and every permission, reachability,
and execution state has deterministic coverage.

### Phase 3: application and command contract

1. Add prompts and renderer without a final confirmation step.
2. Register menu item 34 and canonical dispatch.
3. Update completion and exhaustive command-surface tests.
4. Add command documentation.

Gate: direct module and interactive paths behave identically; EOF at required
input performs no execution.

### Phase 4: disposable live proof

1. Add the dedicated Kind fixture and safe regressions.
2. Prove a denied active token, a qualifying non-active stored token, GET-only
   RBAC, direct TLS, target mutation, negative identities, and independent
   marker assertion.
3. Update Make/CI/aggregate inventory in one serialized change.
4. Confirm cleanup and inspect final repository state.

Gate: the dedicated Kind target passes on the primary worktree and the exact
cluster is confirmed absent afterward.

### Phase 5: final verification

Run and record:

```text
go fmt ./...
go test -race ./internal/kube ./internal/modules/nodesproxyexec ./internal/app
make test-quiet
make build
make nodes-proxy-exec-kind-test
git diff --check
git status --short
```

If the full static build exhausts temporary storage, rerun serially with the
repository's `/tmp` caches and `GOFLAGS=-p=1`; report both the original failure
and the rerun. Do not treat a safe regression suite as proof of the live
kubelet path.

## Acceptance criteria

The feature is complete only when all of the following are true:

- Existing CLI behavior, flags, aliases, build outputs, and deployment paths
  remain unchanged.
- Menu item 34 is available through numeric, canonical `-m`, interactive, and
  completion paths.
- Every token stored at module start receives a node-specific RBAC result; an
  allowed or failed result from one token does not skip later tokens.
- Per-token output identifies only the stored index, sanitized name, discovery
  method, and access state; no token value, JWT payload, prefix, or digest is
  exposed.
- The operator explicitly selects a qualifying token, and scanning or
  selection does not change `session.Connection` or `Session.ServiceAccounts`.
- The selected non-active stored token can authenticate directly to a selected
  kubelet without credential material reaching output or URLs.
- A node-specific `get nodes/proxy` grant with `create nodes/proxy` and
  `create pods/exec` denied can execute one command through WebSocket GET.
- The application reports only `confirmed-get-only-exec` when the negative
  authorization controls and actual command result support it.
- TLS mode defaults to `insecure` and takes effect without a separate warning
  or acknowledgement; verified modes remain available.
- No HTTP POST or SPDY fallback is present.
- Commands, responses, errors, and execution time are bounded.
- Target state is refreshed immediately before execution.
- Unit, race, command-surface, safe shell, build, and dedicated Kind checks
  pass.
- The Kind target independently verifies the side effect and its negative
  controls, then confirms cluster deletion.
- Documentation states both offensive impact and defensive mitigations.
- Final `git status --short` contains only the approved feature paths and any
  unrelated pre-existing user changes.

## Stop conditions

Stop and request a plan amendment if implementation would require:

- changing or replacing item 22;
- using insecure TLS as the only live positive path;
- adding interactive shell or batch execution;
- introducing a non-Kubernetes WebSocket dependency;
- sending credentials through an API-server proxy or redirect;
- weakening access-review failures into authorization success;
- stopping the stored-token scan after the active or first successful token;
- automatically selecting a token or mutating the active session identity;
- printing token material or a token-derived fingerprint;
- requiring broad Node listing for the core path;
- modifying shared Kind cleanup guarantees; or
- expanding into token theft, host escape, persistence, or automatic
  privileged-target selection.
