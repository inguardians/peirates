# Test

## Dependencies

Run `go mod tidy -e` to keep things up to date.

To test the dependencies:

```sh
go list -u -m all # view available minor and patch upgrades for all direct and indirect dependencies
go get -u ./... # upgrades to the latest or minor patch release
go get -t -u ./... # upgrade test dependencies
go test all # run the following command to test that packages are working correctly after an upgrade
```

Additional external test apps and test data.

## Setup

* Install `direnv`

```sh
direnv allow .
```

## Container

* Use these steps to create the container images.
* Go to your packages on Github to verify everything is working.

```sh
cd deployments
make build
make push
make dev
make push-dev
```

## Kind integration test

This opt-in test creates a disposable Kind cluster, grants a temporary service
account read access, and verifies Peirates can list namespaces through the
live Kubernetes API. It requires Docker, Kind, kubectl, and Go. The script
refuses a pre-existing `peirates-integration` cluster (or the exact
`KIND_CLUSTER_NAME` override), records private kubeconfig provenance, and
deletes only a cluster positively owned by the current invocation.

```sh
make kind-test
```

`make kind-test` remains the short namespace API smoke test. To run all 21
automated Kind scenarios serially, use:

```sh
make kind-tests
```

The full suite requires Docker, Kind v0.32.0, kubectl v1.36.1, Go 1.27.0, and
network access for container images and Go modules. It creates one disposable
cluster at a time, uses private temporary kubeconfig files, and stops at the
first failing target. After every target it independently enumerates Kind
clusters and verifies that the exact configured name is absent; an enumeration
error or remaining name fails the aggregate visibly. The aggregate itself
never deletes clusters. Allow roughly 20–30 minutes with warm image and module
caches, and longer on a first run. The intentionally vulnerable
`test/kubelet-kind-manual.sh` harness is not part of the aggregate suite and
must be started and cleaned up explicitly.

All Kind harnesses pin the official Kind v0.32.0 Kubernetes v1.36.1 node image
by digest, matching both the external kubectl and Peirates' embedded
`k8s.io/kubectl` v0.36.1 client. A test workstation may override the image with
`PEIRATES_KIND_NODE_IMAGE`, but CI always supplies the documented digest.

## Security

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# machine readable
# gosec -conf test/.gosec.config.json -track-suppressions -fmt=json -out=test/results.json -stdout ./...
gosec -conf test/.gosec.config.json -track-suppressions ./...
```

Govulncheck

```sh
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
# Run govulncheck
govulncheck ./...
```

## Service-account menu integration test

Run `make service-account-kind-test` to create a disposable Kind cluster and
exercise all seven actions under main-menu option 1 through a Peirates binary
running in a pod: list, switch, add, export, import, decode, and display. The
test uses the pod's real projected service-account JWT, refuses to modify a
pre-existing cluster named `peirates-service-account-integration`, and deletes
the disposable cluster on exit. Override the cluster name with
`PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER`, using a name reserved for this test.

The display assertion still compares the complete raw token in memory, but all
failure diagnostics replace it with `[REDACTED SERVICE ACCOUNT TOKEN]`. The
token belongs only to the disposable cluster and is never written to an
artifact by the test.


## Namespace menu integration test

Run `make namespace-kind-test` to create a disposable Kind cluster and exercise
both actions under main-menu option 2 through a Peirates binary running in a
pod: list namespaces and switch namespace. The pod's default service account is
granted only `get` and `list` on core `namespaces`, plus `get` and `list` on
pods in the target namespace. The switch and a target-scoped pod listing run in
one Peirates process, and the test requires a pod that exists only in the target
namespace to appear after switching. The test refuses to modify a pre-existing
cluster named `peirates-namespace-integration` and deletes its disposable
cluster on exit. Override the name with
`PEIRATES_NAMESPACE_KIND_CLUSTER`, using a name reserved for this test.

## Pod information integration test

Run `make pod-info-kind-test` to create a disposable Kind cluster and exercise
main-menu item 3 (list pods) followed by item 4 (dump complete pod JSON) through
a Peirates binary running in a pod. The pod's default service account is granted
only namespace-scoped `get` and `list` access to core `pods`. The test refuses to
modify a pre-existing cluster named `peirates-pod-info-integration` and deletes
only its dedicated cluster on exit. Override the name with
`PEIRATES_POD_INFO_KIND_CLUSTER`, using a name reserved for this test.

## Volume-mount integration test

Run `make volume-mount-kind-test` to create a disposable Kind cluster and
exercise both paths under main-menu item 5 through a Peirates binary running in
a pod: report hostPath mounts for all pods and for one named pod. The fixture
pod mounts a dedicated, observable hostPath and its default service account is
granted only namespace-scoped `get` and `list` access to core `pods`. The test
refuses to modify a pre-existing cluster named
`peirates-volume-mount-integration` and deletes only its dedicated cluster on
exit. Override the name with `PEIRATES_VOLUME_MOUNT_KIND_CLUSTER`, using a name
reserved for this test.

## Certificate menu integration test

Run `make certificate-menu-kind-test` to create a disposable Kind cluster, copy
Peirates directly onto its control-plane node, and exercise both paths under
main-menu item 9: list discovered client certificate/key pairs and switch to the
live kubelet identity. The test refuses to modify a pre-existing cluster named
`peirates-certificate-integration` and deletes only its dedicated cluster on
exit. Override the name with `PEIRATES_CERTIFICATE_KIND_CLUSTER`, using a name
reserved for this test.

## Anonymous kubelet integration test

Run `make kubelet-kind-test` to create a disposable Kind cluster and prove that
Peirates can list running pods through the unauthenticated read-only kubelet endpoint on port 10255 and execute a command through the anonymous HTTPS kubelet endpoint on port 10250. The test
refuses to use a pre-existing cluster, uses the isolated cluster name
`peirates-kubelet-integration` by default, and deletes that cluster on every exit. The namespace default service account is granted only `get` and `list` on core `nodes`, and setup verifies that permission. It also receives namespace-scoped pod `get`/`list` plus the legacy pod `exec` authorization verb and `pods/exec` `create` permissions so the test can copy Peirates into the target pod and run its `exec-via-api` all-pods path with `id`.
Override the name with `PEIRATES_KUBELET_KIND_CLUSTER`; choose a name reserved for
this disposable test.

This test intentionally configures the disposable node kubelet with anonymous authentication, `AlwaysAllow` authorization, and the read-only port. Those settings permit unauthenticated pod discovery and command execution and are unsafe for any
shared or persistent cluster. The test must never be adapted to target an existing
cluster. Docker, Kind, kubectl, Go, and network access to pull the test image are
required.

All dedicated automated Kind integration scripts use a private temporary
kubeconfig and remove it after deleting their disposable cluster. They do not
change the caller's kubeconfig or current context.

For hands-on kubelet testing, run `test/kubelet-kind-manual.sh`. The manual
harness retains both its intentionally vulnerable cluster and its private
kubeconfig after successful setup, and prints the exact `KUBECONFIG=...`
commands needed to inspect and delete the cluster. Override the generated path
with `PEIRATES_KUBELET_MANUAL_KUBECONFIG=/path/to/new-file`; the path must not
already exist, and a caller-supplied path is never removed automatically. A
relative path is converted to an absolute path for the printed handoff commands.
Colon-separated kubeconfig path lists are rejected because this harness must
retain and report exactly one file.

## Nodes/proxy interactive Kind test

Run `test/nodes-proxy-exec-kind-manual.sh` from an interactive terminal to
exercise `nodes-proxy-exec` by hand against a disposable Kind cluster. This
manual harness is intentionally separate from the 21 automated Kind targets.
It starts Peirates directly in a runner Pod, prints the exact node, stored-token
index, kubelet origin, verified-TLS settings, marker command, and confirmation
string to enter, and asks the operator to choose the displayed row for the
dedicated target container.

The fixture uses an ordinary authenticated, webhook-authorized kubelet. The
runner's active token and one later stored token are denied; only stored token
index `1` receives node-specific `get nodes/proxy`. That identity remains
denied `create nodes/proxy` and `create pods/exec`. The kubelet serving
certificate is mounted as a public trust anchor, so the positive path does not
use insecure TLS.

After Peirates exits, the harness independently checks the documented marker,
reasserts the negative RBAC controls and API health, and automatically removes
its proven-owned cluster and private kubeconfig. Ctrl-C also invokes cleanup.
It refuses a pre-existing cluster named
`peirates-nodes-proxy-manual-cluster`; override the dedicated name with
`PEIRATES_NODES_PROXY_EXEC_MANUAL_CLUSTER`.

## API pod-exec integration test

Run `make exec-via-api-kind-test` to create a disposable Kind cluster and
exercise both interactive branches of main-menu item 21 through a real Peirates
binary running in a pod. The specific-pod branch runs through numeric item `21`
and verifies that a harmless marker is created only in the selected fixture pod.
The all-pods branch runs through `exec-via-api` and verifies a separate marker
in every running test pod.

The runner's default service account receives only namespace-scoped `get`,
`list`, and legacy `exec` access to pods plus `create` access to `pods/exec`.
The test refuses a pre-existing cluster named `peirates-exec-api-integration`
and deletes only the cluster it created. Override the name with
`PEIRATES_EXEC_API_KIND_CLUSTER`, using a name reserved for this test.

## Kubectl authorization-context integration test

Run `make kubectl-try-all-kind-test` to create a disposable Kind cluster and
exercise `kubectl-try-all` and `kubectl-try-all-until-success` through a real
Peirates binary running in-cluster. The runner starts with a denied service
account and discovers two ordered, controller-populated service-account-token
Secrets. The test proves that `kubectl-try-all` continues through every account
and reports both successful API results, while the until-success form continues
past the denied account, reports the first successful result, and never attempts
the later account.

Only the two successful accounts receive namespace-scoped `get` permission for
one fixture ConfigMap. Peirates reads credentials only from mounted Secret
volumes; the script does not retrieve or print token data. The test refuses a
pre-existing cluster named `peirates-kubectl-try-all-integration` and deletes
only its dedicated cluster. Override the name with
`PEIRATES_KUBECTL_TRY_ALL_KIND_CLUSTER`.

## HTTP client integration test

Run `make curl-kind-test` to create a disposable Kind cluster and exercise both
forms of main-menu item 91 through a real Peirates binary running in-cluster.
The test drives numeric item `91` through its interactive request wizard, then
runs the direct `curl -X POST -H Name:Value -d key=value URL` form without the
wizard. For each route, the HTTP fixture requires a POST request, two distinct
custom headers, and two form variables in the request body before returning its
route-specific success marker.

The HTTP server and runner are isolated to the disposable cluster and require
no Kubernetes RBAC permissions. The test refuses a pre-existing cluster named
`peirates-curl-integration` and deletes only the cluster it created. Override
the name with `PEIRATES_CURL_KIND_CLUSTER`, using a name reserved for this test.

## API Secret listing integration test

Run `make list-secrets-kind-test` to create a disposable Kind cluster and test
main-menu item 10 through a real Peirates binary running in-cluster. It verifies
that opaque, TLS, and service-account-token Secrets are listed; that the token
Secret is separately classified as a service account; that the numeric command
and both named aliases work; and that an unprivileged service account receives
the denial path without fixture names being disclosed. The test refuses a
pre-existing `peirates-list-secrets-integration` cluster and deletes only its
dedicated cluster. Override the name with `PEIRATES_LIST_SECRETS_KIND_CLUSTER`.

## Secret-to-service-account integration test

Run `make secret-to-sa-kind-test` to create a disposable Kind cluster and test
main-menu item 11 through a real Peirates binary running in-cluster. The test
creates a real `kubernetes.io/service-account-token` Secret, drives the numeric
interactive item, and verifies the imported account remains available in the
same Peirates session. It also covers the `secret-to-sa` command, its
`get-secret` alias, and rejection of a non-token Secret. The pod's default
service account receives only namespace-scoped `get` access to Secrets. Test
diagnostics redact the fixture token, and successful output never prints it.
The test refuses a pre-existing `peirates-secret-to-sa-integration` cluster and
deletes only its dedicated cluster. Override the name with
`PEIRATES_SECRET_TO_SA_KIND_CLUSTER`.

## HostPath attack-pod integration test

Run `make attack-hostpath-kind-test` to create a disposable Kind cluster and
exercise main-menu item 20 through a real Peirates binary running in-cluster.
The test covers the numeric command, canonical module name, and one historical
alias. For each path, it observes the short-lived attack pod, verifies that its
`hostPath` is `/`, and reads a synthetic marker through the pod's `/root` mount.
It also confirms that the module writes its callback entry into the disposable
Kind node's crontab and removes the attack pod afterward.

The test verifies the callback port is closed and restricts it to `127.0.0.1:65535`.
The Kind configuration
does not mount any path from the physical Docker host. The runner's service
account receives only namespace-scoped pod `get`, `list`, `create`, `delete`,
and `pods/exec` `create` permissions. The test refuses a pre-existing cluster
named `peirates-attack-hostpath-integration`, deletes only a cluster it created,
and removes the module-created resources by deleting that disposable cluster.
Override the name with `PEIRATES_ATTACK_HOSTPATH_KIND_CLUSTER`.

## Node filesystem secret integration test

Run `make nodefs-steal-secrets-kind-test` to create a disposable Kind cluster;
mount synthetic opaque and TLS Secrets plus projected and legacy
service-account tokens into a fixture pod; and copy Peirates directly onto the
control-plane node. The test runs the real `nodefs-steal-secrets` module on that
node and verifies that it classifies all four fixtures under
`/var/lib/kubelet/pods` without printing the token, private key, or opaque
Secret value. The test refuses to modify a
pre-existing cluster named `peirates-nodefs-secrets-integration` and deletes
only its dedicated cluster on exit. Override the name with
`PEIRATES_NODEFS_SECRETS_KIND_CLUSTER`, using a name reserved for this test.

## Privileged hostPID breakout integration test

Run `make hostpid-breakout-kind-test` to create a disposable single-node Kind
cluster and exercise main-menu item 24 through a real static Peirates binary.
The positive runner is a root privileged pod with `hostPID: true`; the test
proves its ordinary container root cannot see a synthetic node marker, enters
the node shell through the numeric command, canonical command, and one alias,
then verifies UID, root directory, marker contents, and PID, mount, UTS, IPC,
and network namespace identities against independent Docker observations.

Two negative controls prove fail-closed behavior: a root hostPID pod without
privilege is rejected for missing capabilities, and a privileged pod without
hostPID is rejected because visible PID 1 has no distinct node root. All three
pods disable service-account-token mounting and receive no RBAC permissions.
The Kind configuration mounts no physical-host path, so the escape reaches
only the disposable Kind node container. The test refuses a pre-existing
cluster named `peirates-hostpid-breakout-integration`, uses the shared private
kubeconfig and ownership protections, and deletes only its proven-owned
cluster. Override the name with `PEIRATES_HOSTPID_BREAKOUT_KIND_CLUSTER`.

## HostPID ptrace breakout integration test

Run `make hostpid-ptrace-breakout-kind-test` to create a disposable Linux AMD64
Kind cluster and exercise menu item 32 against only a uniquely marked root
`sleep` process created by the test inside the Kind node. The runner pod uses
`hostPID: true`, drops every default capability, adds only `SYS_PTRACE`, remains
non-privileged, and uses the runtime-default seccomp profile. The test drives a
harmless command through the PTY-backed interactive shell and exits it cleanly.
It independently compares UID, hostname, working directory, and PID, mount,
and UTS namespace identities with Docker-side observations.

The harness verifies that the original target retains the same PID, start
time, executable, and command line after detach and that no injected shell
remains. Negative controls cover each missing capability, a private PID
namespace, PID 1, a target in another pod's namespace, a test-owned
multithreaded process, wrong confirmation, and target exit. Nested
user-namespace coverage runs only where the node permits creating one; the
harness never changes Yama, seccomp, AppArmor, SELinux, or user-namespace
policy.

Kind proves mechanics relative to its node container only. A disposable VM
whose Kubernetes node is installed directly on an independent kernel remains
the release gate for an outside-all-containers claim. The test refuses a
pre-existing cluster named `peirates-hostpid-ptrace-integration`, uses the
shared fail-closed ownership and private-kubeconfig helpers, and deletes only
its proven-owned cluster. Override the name with
`PEIRATES_HOSTPID_PTRACE_KIND_CLUSTER`.

## Container escape scan integration test

Run `make container-escape-scan-kind-test` to verify that main-menu item 25
assesses container escape prerequisites without mutating its Kubernetes,
nested-Docker, or disposable-node fixtures. The test runs an
architecture-matched static Peirates binary in five Pods: an unprivileged
baseline, a container with a read-only mount of the Kind node root, a client
connected only to a Docker-in-Docker Unix socket, and writable and read-only
mounts of the disposable node's `/var/log` at the same container path.

Tested behavior:

- Numeric item `25`, canonical command `container-escape-scan`, and alias
  `escape-scan` all dispatch through the real binary.
- The baseline reports blocked hostPID, host-root, Docker-socket, and host-proc
  findings, plus an unsupported cgroup v1 `release_agent` finding when the
  independently observed fixture uses cgroup v2.
- The mounted-root fixture reports one available host-root candidate, matching
  the disposable Kind node root observed outside Peirates.
- The nested Docker fixture reports a candidate only after its bounded `_ping`
  and `/version` requests reach the isolated daemon socket.
- The writable host-log fixture reports `hostlog-symlink-read` as a candidate,
  identifies the `/var/log` mount, and states that
  `nodes/proxy` authorization and kubelet `/logs/` access remain unproven.
- The same host-log path mounted read-only reports the technique as blocked.
  Independent writes through both fixtures prove the effective access modes.
- Kind's staged bind mount can hide the original `/var/log` source from
  mountinfo, so this fixture exercises the exact `/var/log` destination
  fallback. Nonstandard container paths qualify only when mountinfo retains a
  root at `/var/log` or one of its descendants.
- Output includes the read-only/not-proof warning and does not disclose a
  sentinel environment value or the node marker contents.
- Before-and-after snapshots prove that no Kubernetes resource, nested Docker
  container, image, volume, or network is created or removed by any scan and
  that the node marker remains unchanged.

The test requires Docker, Kind, kubectl, Go, `timeout`, and network access for
the pinned Kind, BusyBox, and Docker-in-Docker images. It refuses a pre-existing
cluster named `peirates-container-escape-scan-integration`, uses a private
kubeconfig plus the shared ownership guard, and deletes only its proven-owned
cluster. Override the name with
`PEIRATES_CONTAINER_ESCAPE_SCAN_KIND_CLUSTER`, using a name reserved for this
test.

No Pod receives a service-account token or RBAC permission. The Kind node
configuration mounts no physical-host path. The host-root fixture receives
only the disposable Kind node container's `/` at read-only `/hostroot`; the
host-log fixtures receive only that node container's `/var/log`; and the
nested daemon shares only an `emptyDir` socket. The test never exposes the
workstation or CI Docker socket, host procfs, or host cgroup controls.

Kind shares its kernel with its Docker host, so this test does not positively
exercise the kernel-global cgroup v1 `release_agent` or host `core_pattern`
techniques. It verifies only their safe detection, blocked, or unsupported
results. Positive coverage for either technique requires the separately
approved independent-kernel VM harness described in the container-escape plan.

## Host-log symlink read integration test

Run `make hostlog-read-kind-test` to verify that main-menu item 33 reads one
synthetic host file through a writable `/var/log` mount and the disposable
node kubelet's `/logs/` handler. The test exercises numeric item `33`, canonical
command `hostlog-symlink-read`, and alias `hostlog-read` through a real,
architecture-matched static Peirates binary.

Tested behavior:

- A root runner with all capabilities dropped mounts only the Kind node
  container's `/var/log` at the same `/var/log` path; `NODE_NAME` comes from the
  downward API.
- Its dedicated service account receives only `get` on cluster-scoped
  `nodes/proxy`. The test proves it cannot get nodes, list Secrets, or create
  Pods.
- Every dispatch form returns the exact bytes of a synthetic marker under the
  disposable node's `/tmp`, outside `/var/log` and outside the Pod's mounts.
  Each Pod independently proves that the same `/tmp` target path is absent in
  its own filesystem.
- Peirates reports one randomized temporary symlink and removes it before
  returning content. Docker-side checks prove that the exact link and every
  Peirates-prefixed link are absent afterward.
- The marker's device, inode, mode, owner, size, and SHA-256 digest remain
  unchanged, and no ordinary `/var/log/tmp` path exposes the marker.
- A service account without `nodes/proxy` fails endpoint preflight before
  mutation; the same node log directory mounted read-only fails local
  qualification; and a missing target still leaves no temporary link.
- Namespace and test RBAC object inventories remain unchanged, all fixture
  Pods remain Ready, and both the API server and kubelet report healthy.

The single-node Kind configuration explicitly enables
`enableDebuggingHandlers` and `enableSystemLogHandler` while disabling
`enableSystemLogQuery`, which isolates the legacy file-server behavior under
test. Granting `nodes/proxy` is powerful and unsafe on a shared cluster; this
grant exists only in the uniquely named disposable fixture. The Kind
configuration has no `extraMounts`, so the Pod hostPath reaches the Kind node
container rather than the workstation or CI host filesystem.
Kind's staged bind can hide its original source from mountinfo; the same-path
fixture therefore exercises the exact `/var/log` fallback. A nonstandard
container destination is accepted only when mountinfo preserves a root at
`/var/log` or one of its descendants.

The harness refuses a pre-existing cluster named
`peirates-hostlog-read-integration`, uses the shared private-kubeconfig,
cluster-claim, provenance, and fail-closed cleanup protections, and deletes
only its proven-owned cluster. Override the name with
`PEIRATES_HOSTLOG_READ_KIND_CLUSTER`, using a name reserved for this test.

## Docker socket breakout integration test

Run `make docker-socket-breakout-kind-test` to verify that main-menu item 26
uses an exposed Docker-compatible Unix socket to enter only an isolated
Docker-in-Docker daemon container. The test builds and copies an
architecture-matched static Peirates binary into an unprivileged client
container that shares `/var/run/docker.sock` with the nested daemon through an
`emptyDir` volume.

Tested behavior:

- Numeric item `26`, canonical command `docker-socket-breakout`, and alias
  `docker-breakout` select an exact, already-present local image and reach the
  nested daemon's root filesystem and PID namespace.
- Both fixture images declare a non-root default user; the successful path
  proves Peirates explicitly runs its constrained probe and breakout as root.
- UID, working directory, daemon-root marker, root device/inode identity, and
  PID namespace output match observations made independently in the
  Docker-in-Docker sidecar.
- A missing socket fails before image selection or container creation.
- A missing local image returns a Docker API error, explicitly reports that no
  pull was attempted, and does not appear afterward.
- An existing image without `chroot` fails inside the constrained validation
  container before any privileged shell container is started.
- Every positive and negative invocation leaves no container carrying the
  Peirates ownership label, and the complete nested image inventory remains
  unchanged.

The test requires Docker, Kind, kubectl, Go, `timeout`, and network access for
the pinned Kind and Docker-in-Docker images. Its default nested daemon image is
`docker:27.5.1-dind`; override it with
`PEIRATES_DOCKER_SOCKET_DIND_IMAGE` only with a compatible image reserved for
this disposable test. The usable and no-`chroot` fixture images are imported
locally from the running DinD image's BusyBox and libraries, so the nested
daemon performs no registry pull.

The Kind configuration adds no host mount. The client and privileged daemon
share only an `emptyDir` socket directory: the workstation or CI Docker socket
and every physical-host path remain inaccessible. Neither container receives a
service-account token or RBAC permission. The resulting shell controls the
nested daemon container, not the Kind node or the physical Docker host.

The harness refuses a pre-existing cluster named
`peirates-docker-socket-breakout-integration`, uses the shared private
kubeconfig and fail-closed ownership protections, and deletes only its
proven-owned cluster. Override the name with
`PEIRATES_DOCKER_SOCKET_BREAKOUT_KIND_CLUSTER`, using a name reserved for this
test. The EXIT cleanup removes the cluster after checking every
Peirates-labeled nested container by exact daemon state.

## Mounted host-root breakout integration test

Run `make hostroot-breakout-kind-test` to verify that main-menu item 27 changes
only an isolated Peirates worker's filesystem root to an existing read-only
mount of the disposable Kind node root. The test uses an
architecture-matched static binary and requires no namespace entry or external
`chroot` executable.

Tested behavior:

- Numeric item `27`, canonical command `hostroot-breakout`, and alias
  `host-root-breakout` select `/hostroot`, open a shell, and return cleanly
  after `exit`.
- Shell UID, working directory, marker contents, and root device/inode identity
  match state observed independently through Docker before Peirates runs.
- A root container without `CAP_SYS_CHROOT` fails before a worker starts even
  though it can read the mounted node root.
- A privileged container without the mount fails automatic discovery, and `/`
  is rejected as a substitute for a distinct mounted root.
- The disposable node marker remains unchanged after every read-only shell
  check.

The test requires Docker, Kind, kubectl, Go, `timeout`, and network access for
the pinned Kind and BusyBox images. All Pods disable service-account-token
mounting and receive no RBAC permissions. The `/hostroot` volume is read-only,
and the Kind configuration exposes no physical-host path; the shell reaches
only the disposable Kind node container filesystem and does not enter its PID,
mount, network, IPC, UTS, user, cgroup, or time namespaces.

The harness refuses a pre-existing cluster named
`peirates-hostroot-breakout-integration`, uses a private kubeconfig and the
shared fail-closed ownership guard, and deletes only its proven-owned cluster.
Override the name with `PEIRATES_HOSTROOT_BREAKOUT_KIND_CLUSTER`, using a name
reserved for this test. Deleting that disposable cluster also removes the
fixture marker and every test Pod; the module itself leaves no persistent
resource to clean up.
