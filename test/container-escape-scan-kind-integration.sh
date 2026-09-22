#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates assesses container
# escape prerequisites without changing the disposable node, Kubernetes API,
# or an isolated nested Docker daemon.
#
# It tests:
# - numeric, canonical, and alias dispatch through a real static Peirates binary
# - blocked baseline findings in an unprivileged container
# - an available mounted-root finding backed by the disposable Kind node root
# - a candidate Docker-socket finding backed only by a nested Docker-in-Docker daemon
# - writable and read-only host /var/log mount classification without endpoint probing
# - cgroup v2 unsupported and host-proc core-pattern blocked findings
# - operation without service-account credentials or RBAC
# - preservation of Kubernetes, Docker, and node-marker state across every scan

# Stop immediately on setup, command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define the isolated cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_CONTAINER_ESCAPE_SCAN_KIND_CLUSTER:-peirates-container-escape-scan-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-container-escape-scan-test"
baseline_pod="peirates-scan-baseline"
hostroot_pod="peirates-scan-hostroot"
docker_pod="peirates-scan-nested-docker"
hostlog_writable_pod="peirates-scan-hostlog-writable"
hostlog_readonly_pod="peirates-scan-hostlog-readonly"
hostlog_mount="/var/log"
hostlog_probe_name=".peirates-hostlog-scan-write-probe"
nested_socket="/run/nested-docker/docker.sock"
marker_path="/peirates-container-escape-scan-marker"
marker_value="peirates-container-escape-scan-node-root"
secret_sentinel="peirates-scan-secret-must-not-appear"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only the proven-owned cluster and this run's temporary files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-container-escape-scan-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-container-escape-scan-binary.XXXXXX)"

# Verify required tools, serialize this cluster name, and fail closed if it exists.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create one disposable node with no physical-host mounts. The only later
# hostPath is the root of this disposable Kind node container itself.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

# Create a harmless marker only in the disposable Kind node root and record its
# identity independently through the outer Docker daemon.
docker exec "${node_name}" sh -c "printf '%s\n' '${marker_value}' > '${marker_path}'"
node_root_identity="$(docker exec "${node_name}" stat -c '%d:%i' /)"

# Create five isolated fixtures. No Pod receives a service-account token. The
# scanner Pod never receives host procfs, cgroups, or a host Docker socket. Its
# Docker socket is an emptyDir shared only with the nested daemon sidecar. Both
# host-log mounts expose only /var/log inside the disposable Kind node.
kubectl --context "${context}" -n "${namespace}" apply -f - <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${baseline_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: scanner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: SCANNER_SECRET_SENTINEL
      value: ${secret_sentinel}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${hostroot_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: scanner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: SCANNER_SECRET_SENTINEL
      value: ${secret_sentinel}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
        add: ["SYS_CHROOT"]
    volumeMounts:
    - name: node-root
      mountPath: /hostroot
      readOnly: true
  volumes:
  - name: node-root
    hostPath:
      path: /
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${docker_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: scanner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: DOCKER_HOST
      value: unix://${nested_socket}
    - name: SCANNER_SECRET_SENTINEL
      value: ${secret_sentinel}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: nested-docker-socket
      mountPath: /run/nested-docker
  - name: daemon
    image: docker:27.5.1-dind
    command: ["dockerd"]
    args:
    - --host=unix://${nested_socket}
    - --storage-driver=vfs
    - --tls=false
    - --group=0
    env:
    - name: DOCKER_TLS_CERTDIR
      value: ""
    securityContext:
      privileged: true
    volumeMounts:
    - name: nested-docker-socket
      mountPath: /run/nested-docker
  volumes:
  - name: nested-docker-socket
    emptyDir: {}
---
apiVersion: v1
kind: Pod
metadata:
  name: ${hostlog_writable_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: scanner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: SCANNER_SECRET_SENTINEL
      value: ${secret_sentinel}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-logs
      mountPath: ${hostlog_mount}
  volumes:
  - name: node-logs
    hostPath:
      path: /var/log
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${hostlog_readonly_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: scanner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: SCANNER_SECRET_SENTINEL
      value: ${secret_sentinel}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-logs
      mountPath: ${hostlog_mount}
      readOnly: true
  volumes:
  - name: node-logs
    hostPath:
      path: /var/log
      type: Directory
PODS
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=180s

# Wait for the nested daemon itself, then prove from outside Peirates that the
# exposed socket controls only that empty Docker-in-Docker instance.
for _ in $(seq 1 60); do
    if kubectl --context "${context}" -n "${namespace}" exec "${docker_pod}" -c daemon -- \
        docker -H "unix://${nested_socket}" info >/dev/null 2>&1; then
        nested_docker_ready=true
        break
    fi
    sleep 1
done
if [[ "${nested_docker_ready:-false}" != true ]]; then
    echo "nested Docker daemon did not become ready" >&2
    exit 1
fi

# Build one CGO-disabled static binary for the node architecture and install it
# in scanner containers using the operator kubeconfig, never an in-Pod token.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
for pod in "${baseline_pod}" "${hostroot_pod}" "${docker_pod}" \
    "${hostlog_writable_pod}" "${hostlog_readonly_pod}"; do
    kubectl --context "${context}" -n "${namespace}" cp -c scanner \
        "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -c scanner -- \
        chmod 0755 /tmp/peirates
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -c scanner -- \
        test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
done

# Establish fixture state independently before scanning: private baseline
# process/root state, cgroup v2, the distinct mounted node root, and the nested
# Unix socket and daemon response.
if ! kubectl --context "${context}" -n "${namespace}" exec "${baseline_pod}" -c scanner -- \
    sh -c 'test "$(stat -c "%d:%i" /)" = "$(stat -Lc "%d:%i" /proc/1/root)"'; then
    echo "baseline visible PID 1 root does not resolve to the container root" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" exec "${baseline_pod}" -c scanner -- \
    sh -c 'grep -q "^0::" /proc/self/cgroup && test -r /sys/fs/cgroup/cgroup.controllers'
kubectl --context "${context}" -n "${namespace}" exec "${baseline_pod}" -c scanner -- \
    sh -c 'test ! -S /var/run/docker.sock && test ! -S /run/docker.sock'
runner_root_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${hostroot_pod}" -c scanner -- stat -c '%d:%i' /)"
mounted_root_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${hostroot_pod}" -c scanner -- stat -c '%d:%i' /hostroot)"
if [[ "${runner_root_identity}" == "${node_root_identity}" ||
    "${mounted_root_identity}" != "${node_root_identity}" ]]; then
    echo "mounted-root fixture does not isolate the disposable node root" >&2
    printf 'runner=%s mounted=%s node=%s\n' \
        "${runner_root_identity}" "${mounted_root_identity}" "${node_root_identity}" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" exec "${hostroot_pod}" -c scanner -- \
    test -x /hostroot/bin/sh
kubectl --context "${context}" -n "${namespace}" exec "${docker_pod}" -c scanner -- \
    test -S "${nested_socket}"
kubectl --context "${context}" -n "${namespace}" exec "${docker_pod}" -c scanner -- \
    sh -c 'test ! -S /var/run/docker.sock && test ! -e /hostroot'

# Prove both host-log fixtures map the disposable node's /var/log at the same
# container path, and prove only the writable fixture can mutate it. Kind's
# staged bind mount can hide /var/log from mountinfo Root, so this exercises the
# exact-destination fallback without treating arbitrary writable mounts as logs.
node_log_identity="$(docker exec "${node_name}" stat -c '%d:%i' /var/log)"
writable_log_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${hostlog_writable_pod}" -c scanner -- stat -c '%d:%i' "${hostlog_mount}")"
readonly_log_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${hostlog_readonly_pod}" -c scanner -- stat -c '%d:%i' "${hostlog_mount}")"
if [[ "${writable_log_identity}" != "${node_log_identity}" ||
    "${readonly_log_identity}" != "${node_log_identity}" ]]; then
    echo "host-log fixtures do not map the disposable node /var/log" >&2
    printf 'node=%s writable=%s read-only=%s\n' \
        "${node_log_identity}" "${writable_log_identity}" "${readonly_log_identity}" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" exec "${hostlog_writable_pod}" -c scanner -- \
    sh -c "printf probe > '${hostlog_mount}/${hostlog_probe_name}'"
docker exec "${node_name}" test -f "/var/log/${hostlog_probe_name}"
kubectl --context "${context}" -n "${namespace}" exec "${hostlog_writable_pod}" -c scanner -- \
    rm -f -- "${hostlog_mount}/${hostlog_probe_name}"
docker exec "${node_name}" test ! -e "/var/log/${hostlog_probe_name}"
if kubectl --context "${context}" -n "${namespace}" exec "${hostlog_readonly_pod}" -c scanner -- \
    sh -c "printf probe > '${hostlog_mount}/${hostlog_probe_name}'" 2>/dev/null; then
    echo "read-only host-log fixture unexpectedly accepted a write" >&2
    exit 1
fi
docker exec "${node_name}" test ! -e "/var/log/${hostlog_probe_name}"
if [[ -n "$(docker exec "${node_name}" find /var/log -maxdepth 1 \
    -name '.peirates-hostlog-*' -print -quit)" ]]; then
    echo "host-log fixture started with a Peirates temporary path" >&2
    exit 1
fi

# Snapshot all namespace-scoped resources and all nested Docker object IDs.
# These exact snapshots must remain unchanged after all scan invocations.
kubernetes_before="$(kubectl --context "${context}" -n "${namespace}" get \
    pod,service,configmap,secret,serviceaccount,role,rolebinding,job,cronjob \
    -o name --ignore-not-found | LC_ALL=C sort)"
nested_docker_before="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${docker_pod}" -c daemon -- sh -c \
    "docker -H unix://${nested_socket} ps -aq; docker -H unix://${nested_socket} image ls -aq; docker -H unix://${nested_socket} volume ls -q; docker -H unix://${nested_socket} network ls -q" \
    | LC_ALL=C sort)"

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "container escape scan ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

assert_read_only_output() {
    local output="$1" scenario="$2"
    assert_contains "${output}" \
        "Container escape assessment (read-only; findings are not proof of escape):" \
        "${scenario} warning"
    if [[ "${output}" == *"${secret_sentinel}"* || "${output}" == *"${marker_value}"* ]]; then
        echo "container escape scan ${scenario} exposed fixture content" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Exercise numeric dispatch in the unprivileged baseline and compare stable
# blocked/unsupported findings to the independently observed fixture state.
baseline_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec \
    "${baseline_pod}" -c scanner -- /tmp/peirates -c -m 25 2>&1)"
assert_contains "${baseline_output}" "Attempting menu option 25" "numeric dispatch"
assert_read_only_output "${baseline_output}" "baseline"
assert_contains "${baseline_output}" "[blocked] hostpid-breakout:" "baseline hostPID"
assert_contains "${baseline_output}" "[blocked] hostpid-ptrace-breakout:" "baseline hostPID ptrace"
assert_contains "${baseline_output}" "[blocked] hostroot-breakout:" "baseline host root"
assert_contains "${baseline_output}" "[blocked] docker-socket-breakout:" "baseline Docker socket"
assert_contains "${baseline_output}" "[unsupported] cgroup-release-agent-breakout:" "baseline cgroup v2"
assert_contains "${baseline_output}" "[blocked] hostproc-core-pattern-breakout:" "baseline host procfs"
assert_contains "${baseline_output}" "[blocked] hostlog-symlink-read:" "baseline host log"

# Exercise canonical dispatch where an independently qualified disposable node
# root is mounted. No shell is launched and the marker content is never read.
hostroot_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec \
    "${hostroot_pod}" -c scanner -- /tmp/peirates -c -m container-escape-scan 2>&1)"
assert_contains "${hostroot_output}" \
    "Attempting menu option container-escape-scan" "canonical dispatch"
assert_read_only_output "${hostroot_output}" "host-root fixture"
assert_contains "${hostroot_output}" \
    "[available] hostroot-breakout: one distinct mounted host root is available" \
    "host-root candidate"
assert_contains "${hostroot_output}" \
    "one distinct root-mounted filesystem candidate was found" "host-root evidence"

# Exercise one alias against the nested Unix socket. The stable candidate result
# must identify only the emptyDir socket and must not enumerate Docker objects.
docker_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec \
    "${docker_pod}" -c scanner -- /tmp/peirates -c -m escape-scan 2>&1)"
assert_contains "${docker_output}" "Attempting menu option escape-scan" "alias dispatch"
assert_read_only_output "${docker_output}" "nested Docker fixture"
assert_contains "${docker_output}" "[candidate] docker-socket-breakout:" \
    "nested Docker candidate"
assert_contains "${docker_output}" \
    "Docker-compatible API responded on ${nested_socket} (API " "nested Docker evidence"

# Verify that a writable direct /var/log mount is only a candidate because the
# read-only scanner deliberately does not test RBAC or the kubelet endpoint.
hostlog_writable_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec \
    "${hostlog_writable_pod}" -c scanner -- /tmp/peirates -c -m container-escapes 2>&1)"
assert_contains "${hostlog_writable_output}" \
    "Attempting menu option container-escapes" "writable host-log dispatch"
assert_read_only_output "${hostlog_writable_output}" "writable host-log fixture"
assert_contains "${hostlog_writable_output}" \
    "[candidate] hostlog-symlink-read: one writable host-log mount is locally usable; nodes/proxy and kubelet /logs/ endpoint access remain unproven" \
    "writable host-log candidate"
assert_contains "${hostlog_writable_output}" \
    "qualified mount ${hostlog_mount} maps to logical kubelet /logs/ with rw and effective write/search access; mountinfo did not retain a /var/log root, so hostPath origin remains unproven" \
    "writable host-log evidence"
assert_contains "${hostlog_writable_output}" \
    "nodes/proxy authorization and kubelet /logs/ endpoint access were not tested" \
    "writable host-log unproven endpoint"

# Verify that mounting the same node directory read-only blocks the primitive.
hostlog_readonly_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec \
    "${hostlog_readonly_pod}" -c scanner -- /tmp/peirates -c -m container-escape-scan 2>&1)"
assert_read_only_output "${hostlog_readonly_output}" "read-only host-log fixture"
assert_contains "${hostlog_readonly_output}" \
    "[blocked] hostlog-symlink-read: no writable direct mount rooted at /var/log with effective write and search access was found" \
    "read-only host-log blocker"

# Prove the scan created no Kubernetes or nested-Docker object and did not
# alter the disposable node marker.
kubernetes_after="$(kubectl --context "${context}" -n "${namespace}" get \
    pod,service,configmap,secret,serviceaccount,role,rolebinding,job,cronjob \
    -o name --ignore-not-found | LC_ALL=C sort)"
nested_docker_after="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${docker_pod}" -c daemon -- sh -c \
    "docker -H unix://${nested_socket} ps -aq; docker -H unix://${nested_socket} image ls -aq; docker -H unix://${nested_socket} volume ls -q; docker -H unix://${nested_socket} network ls -q" \
    | LC_ALL=C sort)"
if [[ "${kubernetes_after}" != "${kubernetes_before}" ]]; then
    echo "Kubernetes resources changed during container escape scans" >&2
    diff <(printf '%s\n' "${kubernetes_before}") <(printf '%s\n' "${kubernetes_after}") >&2 || true
    exit 1
fi
if [[ "${nested_docker_after}" != "${nested_docker_before}" ]]; then
    echo "nested Docker resources changed during container escape scans" >&2
    diff <(printf '%s\n' "${nested_docker_before}") <(printf '%s\n' "${nested_docker_after}") >&2 || true
    exit 1
fi
if [[ "$(docker exec "${node_name}" cat "${marker_path}")" != "${marker_value}" ]]; then
    echo "disposable node marker changed during container escape scans" >&2
    exit 1
fi
if [[ -n "$(docker exec "${node_name}" find /var/log -maxdepth 1 \
    -name '.peirates-hostlog-*' -print -quit)" ]]; then
    echo "container escape scan left a temporary host-log path behind" >&2
    exit 1
fi

echo "main-menu item 25 passed live read-only container escape scan integration testing"
