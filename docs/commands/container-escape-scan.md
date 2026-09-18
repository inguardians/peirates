# Container escape prerequisite scan

## Menu entry

- **Menu item:** `25`
- **Canonical command:** `container-escape-scan`
- **Aliases:** `escape-scan`, `container-escapes`
- **Maturity:** Stable read-only assessment on Linux

## Purpose

Inspect the current container for observable prerequisites associated with a
small, reviewed set of container escape techniques. The scan helps an
authorized operator decide which dedicated module, if any, is worth reviewing
next. It does not attempt an escape and does not claim that a candidate reaches
the physical Kubernetes node.

The scan is safe to run as a first step because it is deliberately read-only.
It never creates or starts a container, pulls or enumerates images, mounts a
filesystem, writes a cgroup or sysctl, launches a payload, enters a namespace,
or reads Kubernetes credentials.

## Prerequisites and authorization

Linux provides the local process, namespace, mount, cgroup, and Unix-socket
interfaces used by the scanner. On other operating systems, every technique is
reported as unsupported. Individual checks may also be blocked by procfs mount
restrictions, filesystem permissions, an LSM, seccomp, or a container runtime.

No Kubernetes API access, RBAC permission, service-account token, `kubectl`,
Docker CLI, `curl`, `nsenter`, or external helper is required. A Docker socket
probe uses Peirates' bounded HTTP client directly over an existing Unix socket.

Run the command only in a container and environment you are authorized to
assess. A positive prerequisite finding identifies powerful local access and
can itself be security-sensitive operational information.

## Usage

Select the function from the full interactive menu with any supported form:

```text
25
container-escape-scan
escape-scan
container-escapes
```

Direct module invocation is also supported:

```sh
peirates -c -m container-escape-scan
```

The command takes no prompt input. By default it checks absolute `unix://`
paths from `DOCKER_HOST`, followed by `/var/run/docker.sock` and
`/run/docker.sock`. TCP, SSH, malformed, relative, symbolic-link, and regular
file endpoints are not contacted.

## What it checks

Peirates reads only the local interfaces needed to assess these techniques:

- effective UID and capabilities from `/proc/self/status`;
- PID, mount, user, network, IPC, UTS, and cgroup namespace identities for the
  current process and visible PID 1;
- current-root, visible-PID-1-root, and mounted-root filesystem identities;
- `/proc/self/mountinfo`, including procfs, cgroup, and overlay metadata;
- `/proc/self/cgroup` and cgroup v1 or v2 topology;
- existence and access modes for `release_agent` and `notify_on_release` in
  the same cgroup v1 hierarchy, and for
  `sys/kernel/core_pattern`; and
- Docker `_ping` and `/version` responses through qualifying Unix sockets.

Docker responses are subject to connection, overall-operation, and response
size limits. Peirates requests no container, image, environment, filesystem,
credential, or runtime inventory from the daemon.

The scan emits one result for each reviewed technique:

- `hostpid-breakout`: existing privileged hostPID namespace entry;
- `hostroot-breakout`: entry into an already-mounted, distinct filesystem root;
- `docker-socket-breakout`: creation of a disposable privileged container
  through an exposed Docker-compatible daemon;
- `cgroup-release-agent-breakout`: cgroup v1 `release_agent`, detection only;
- `hostproc-core-pattern-breakout`: writable `core_pattern` exposed by a procfs
  mount. This remains a kernel-global candidate rather than proof that the
  action will succeed or reach the intended host;
- `hostpid-ptrace-breakout`: effective UID 0, matching visible-PID-1 PID and
  user namespaces, and effective `CAP_SYS_PTRACE`. An explicit eligible
  disposable process must still be selected by the action; and
- `hostlog-symlink-read`: a direct, writable, searchable mount rooted at the
  node's `/var/log` directory or a normalized descendant. The local scanner
  does not contact Kubernetes or prove that the kubelet `/logs/` handler and
  `nodes/proxy` authorization are available.

The cgroup technique remains assessment-only. The core-pattern action is a
separate, explicitly confirmed command; the scanner itself remains read-only
and never invokes it.

## Finding statuses

- `available` means all prerequisites that Peirates can safely observe for an
  implemented action are present. It is still not proof that the action will
  succeed or reach the intended host.
- `candidate` means the read-only checks found a plausible path, but mutation
  or operator selection would be required to prove it. Docker socket findings
  remain candidates because the scanner intentionally does not enumerate
  images. Kernel-global techniques also remain candidates.
- `blocked` means at least one required observable prerequisite is absent,
  inaccessible, or ambiguous.
- `unsupported` means the operating system or active cgroup version cannot
  support that technique.

Each summary states the checked prerequisite or blocker. Counts and local paths
may be included as evidence, but the scan does not print file contents,
environment-variable values, Docker inventory, or credentials.

## Expected output

Output begins with an explicit read-only warning and then one deterministic
line per technique:

```text
Container escape assessment (read-only; findings are not proof of escape):
[blocked] hostpid-breakout: ...
[blocked] hostpid-ptrace-breakout: ...
[available] hostroot-breakout: ...
[candidate] hostlog-symlink-read: ...
[candidate] docker-socket-breakout: ...
[unsupported] cgroup-release-agent-breakout: ...
[blocked] hostproc-core-pattern-breakout: ...
```

Indented evidence lines explain successful checks. Exact results depend on the
container's namespaces, capabilities, mounts, runtime, cgroup version, and
socket exposure.

## Side effects and cleanup

The scan performs no intentional mutation and creates no cleanup obligation.
It reads procfs and metadata, checks path access, and sends exactly two safe
HTTP `GET` requests to each qualifying Docker-compatible Unix socket. It does
not retain a daemon connection after the bounded probe completes.

The scan never contacts a TCP or SSH Docker endpoint. A reachable daemon may
control a nested daemon, a virtual machine, or another remote host rather than
the physical Kubernetes node; the operator must establish that boundary
independently before using an action module.

## Failure modes and limitations

- A non-Linux build reports all techniques as unsupported.
- Missing or malformed proc status, mountinfo, cgroup, namespace, or filesystem
  metadata causes the affected finding to fail closed.
- More than one mounted-root candidate requires explicit selection in the
  dedicated host-root command.
- More than one qualifying host-log mount requires explicit selection in the
  dedicated host-log command. Detection checks mount metadata and effective
  write/search access without creating a file or symlink.
- Some Kubernetes runtimes report `/` or a runtime-specific mountinfo root for
  staged hostPath binds. The scanner accepts this only at the exact container
  destination `/var/log` and labels the hostPath origin unproven; arbitrary
  destinations do not use this fallback.
- A missing, non-socket, symbolic-link, permission-denied, non-responsive, or
  incompatible Docker endpoint is never treated as a candidate.
- A Docker endpoint can pass `_ping` and `/version` but lack a usable existing
  image or control a host other than the expected node.
- Cgroup v2 does not support the cgroup v1 `release_agent` technique.
- Writable access checks can be denied later by seccomp, AppArmor, SELinux, or
  another LSM; a positive check is not proof that a write would succeed.
- Overlay `upperdir` values are host-path candidates derived from mount
  metadata. Their presence does not prove that a payload path is host-visible.
- A writable `core_pattern` is kernel-global, but the read-only scan cannot
  prove that the initial-namespace handler will start or identify which
  physical machine owns that kernel.
- Runtime CVEs, kernel-memory exploits, device manipulation, module loading,
  and persistence mechanisms are intentionally outside this scanner's scope.

## Implementation and tests

- [Scanner implementation](../../internal/modules/containerescape)
- [Shared read-only helpers](../../internal/modules/escapeutil)
- [Application registration](../../internal/app/module_registry.go)
- [Unit tests](../../internal/modules/containerescape/scanner_linux_test.go)
- [Disposable Kind integration test](../../test/container-escape-scan-kind-integration.sh)
