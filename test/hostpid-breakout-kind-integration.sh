#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can enter a disposable
# node from a root privileged hostPID pod without an external nsenter binary.
#
# It tests:
# - numeric, canonical, and alias dispatch through a real Peirates binary
# - node-root access and PID, mount, UTS, IPC, and network namespace identity
# - return from the interactive host shell after an explicit exit
# - fail-closed behavior without privilege and without hostPID
# - operation without Kubernetes API credentials inside the runner pods

# Stop immediately on setup, command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define the isolated cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_HOSTPID_BREAKOUT_KIND_CLUSTER:-peirates-hostpid-breakout-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-hostpid-breakout-test"
hostpid_pod="peirates-hostpid-privileged"
unprivileged_pod="peirates-hostpid-unprivileged"
private_pid_pod="peirates-private-pid-privileged"
marker_path="/peirates-hostpid-disposable-marker"
marker_value="peirates-hostpid-node-root"
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
config_file="$(mktemp /tmp/peirates-hostpid-breakout-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-hostpid-breakout-binary.XXXXXX)"

# Verify required tools, serialize this cluster name, and fail closed if it exists.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create a single disposable node without mounting any physical-host paths.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

# Create the namespace before performing Docker-side fixture setup. This also
# gives the ownership regression harness a deterministic post-create command.
kubectl --context "${context}" create namespace "${namespace}"

# Place a harmless marker only in the disposable Kind node root and record the
# node PID 1 namespace identities for independent comparison with the shell.
docker exec "${node_name}" sh -c "printf '%s\\n' '${marker_value}' > '${marker_path}'"
node_pid_namespace="$(docker exec "${node_name}" readlink /proc/1/ns/pid)"
node_mount_namespace="$(docker exec "${node_name}" readlink /proc/1/ns/mnt)"
node_uts_namespace="$(docker exec "${node_name}" readlink /proc/1/ns/uts)"
node_ipc_namespace="$(docker exec "${node_name}" readlink /proc/1/ns/ipc)"
node_network_namespace="$(docker exec "${node_name}" readlink /proc/1/ns/net)"

# Create one qualifying pod and two negative controls. None receives a service
# account token because the breakout uses only local Linux process state.
kubectl --context "${context}" -n "${namespace}" apply -f - <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${hostpid_pod}
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
---
apiVersion: v1
kind: Pod
metadata:
  name: ${unprivileged_pod}
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Pod
metadata:
  name: ${private_pid_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
PODS
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=120s

# Build one static binary for the node architecture and install it in all pods.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
for pod in "${hostpid_pod}" "${unprivileged_pod}" "${private_pid_pod}"; do
    kubectl --context "${context}" -n "${namespace}" cp \
        "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- chmod 0755 /tmp/peirates
done

# Confirm the qualifying container cannot see the node marker before entry.
if kubectl --context "${context}" -n "${namespace}" exec "${hostpid_pod}" -- \
    test -e "${marker_path}" >/dev/null 2>&1; then
    echo "node marker was visible in the hostPID pod before breakout" >&2
    exit 1
fi

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "hostPID breakout ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Run a dispatch form, issue read-only checks in the resulting host shell, and
# verify those checks against state observed independently from Docker.
run_positive_case() {
    local module="$1" output
    if ! output="$({
        printf '%s\n' \
            'printf "HOSTPID_UID=%s\n" "$(id -u)"' \
            'printf "HOSTPID_PWD=%s\n" "$(pwd)"' \
            "printf 'HOSTPID_MARKER=%s\\n' \"\$(cat '${marker_path}')\"" \
            'printf "HOSTPID_PID=%s\n" "$(readlink /proc/self/ns/pid)"' \
            'printf "HOSTPID_MNT=%s\n" "$(readlink /proc/self/ns/mnt)"' \
            'printf "HOSTPID_UTS=%s\n" "$(readlink /proc/self/ns/uts)"' \
            'printf "HOSTPID_IPC=%s\n" "$(readlink /proc/self/ns/ipc)"' \
            'printf "HOSTPID_NET=%s\n" "$(readlink /proc/self/ns/net)"' \
            'exit'
    } | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${hostpid_pod}" -- \
        /tmp/peirates -c -m "${module}" 2>&1)"; then
        echo "hostPID breakout failed for ${module}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi

    assert_contains "${output}" "Attempting menu option ${module}" "${module} dispatch"
    assert_contains "${output}" "Entering PID 1's host namespaces; exit returns to Peirates." "${module} boundary"
    assert_contains "${output}" "HOSTPID_UID=0" "${module} UID"
    assert_contains "${output}" "HOSTPID_PWD=/" "${module} working directory"
    assert_contains "${output}" "HOSTPID_MARKER=${marker_value}" "${module} node root"
    assert_contains "${output}" "HOSTPID_PID=${node_pid_namespace}" "${module} PID namespace"
    assert_contains "${output}" "HOSTPID_MNT=${node_mount_namespace}" "${module} mount namespace"
    assert_contains "${output}" "HOSTPID_UTS=${node_uts_namespace}" "${module} UTS namespace"
    assert_contains "${output}" "HOSTPID_IPC=${node_ipc_namespace}" "${module} IPC namespace"
    assert_contains "${output}" "HOSTPID_NET=${node_network_namespace}" "${module} network namespace"
}

# Exercise the numbered item, canonical command, and one named alias.
for module in 24 hostpid-breakout host-pid-breakout; do
    run_positive_case "${module}"
done

# A root hostPID pod without privilege must fail before launching a worker.
if ! unprivileged_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" \
    exec "${unprivileged_pod}" -- /tmp/peirates -c -m hostpid-breakout 2>&1)"; then
    echo "unprivileged negative control exited unexpectedly" >&2
    printf '%s\n' "${unprivileged_output}" >&2
    exit 1
fi
assert_contains "${unprivileged_output}" \
    "required effective capabilities are missing: CAP_SYS_ADMIN" "unprivileged control"
if [[ "${unprivileged_output}" == *"${marker_value}"* ||
    "${unprivileged_output}" == *"Entering PID 1's host namespaces"* ]]; then
    echo "unprivileged negative control reached the host worker" >&2
    printf '%s\n' "${unprivileged_output}" >&2
    exit 1
fi

# A privileged pod with a private PID namespace sees its own root as PID 1 and
# must fail the distinct-node-root qualification check.
if ! private_pid_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" \
    exec "${private_pid_pod}" -- /tmp/peirates -c -m breakout-hostpid 2>&1)"; then
    echo "private-PID negative control exited unexpectedly" >&2
    printf '%s\n' "${private_pid_output}" >&2
    exit 1
fi
assert_contains "${private_pid_output}" "no distinct node root is visible" "private-PID control"
if [[ "${private_pid_output}" == *"${marker_value}"* ||
    "${private_pid_output}" == *"Entering PID 1's host namespaces"* ]]; then
    echo "private-PID negative control reached the host worker" >&2
    printf '%s\n' "${private_pid_output}" >&2
    exit 1
fi

# Report completion after positive entry and both fail-closed controls pass.
echo "main-menu item 24 passed live hostPID breakout integration testing"
