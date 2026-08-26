#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can discover host-backed
# volume mount points through both interactive paths of the find-volume-mounts item.
#
# The script tests:
# - Creating an isolated Kind cluster with minimally scoped pod-read permissions.
# - Detecting a known hostPath mount while scanning all pods in a namespace.
# - Detecting the same hostPath mount when selecting one target pod.

# Enable strict shell error handling so failed setup or assertions stop the test.
set -euo pipefail

# Resolve repository paths and define the temporary and Kubernetes test resources.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_VOLUME_MOUNT_KIND_CLUSTER:-peirates-volume-mount-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-volume-mount-test"
pod_name="peirates-volume-mount-target"
role_name="peirates-volume-mount-reader"
host_path="/tmp/peirates-observable-host-volume"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_owned=false

# Remove test-owned cluster and temporary files on every exit path.
cleanup() {
    trap '' INT TERM
    if [[ "${cluster_owned}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-volume-mount-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-volume-mount-binary.XXXXXX)"

# Verify required tools are installed and avoid modifying a pre-existing cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the disposable Kind cluster and grant its default service account pod-read access.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_owned=true
kind create cluster --name "${cluster_name}" --config "${config_file}" \
    --image "$(kind_node_image)" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get,list --resource=pods
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:default"
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" pods \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} pods" >&2
        exit 1
    fi
done

# Deploy a target pod with a known hostPath volume and wait until it is ready.
kubectl --context "${context}" -n "${namespace}" apply -f - <<POD
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  labels:
    peirates-test: volume-mount
spec:
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: observable-host-volume
      mountPath: /mnt/observable-host-volume
  volumes:
  - name: observable-host-volume
    hostPath:
      path: ${host_path}
      type: DirectoryOrCreate
POD
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

# Build Peirates for the Kind node, copy it into the target pod, and make it executable.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

# Define helpers for driving the menu item and asserting its reported mount paths.
run_volume_mount_item() {
    local input="$1"
    printf '%s' "${input}" | timeout 90s kubectl --context "${context}" -n "${namespace}" \
        exec -i "${pod_name}" -- /tmp/peirates -c -m find-volume-mounts
}
assert_contains() {
    local output="$1" expected="$2" path_name="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "main-menu item 5 ${path_name} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Exercise the all-pods path and verify it identifies the target pod and host mount.
all_output="$(run_volume_mount_item $'all\n' 2>&1)"
assert_contains "${all_output}" "Host Mount Point: ${host_path} found for pod ${pod_name}" "all-pods path"

# Exercise the single-pod path and verify its heading and discovered host mount.
single_output="$(run_volume_mount_item $'single\n'"${pod_name}"$'\n' 2>&1)"
assert_contains "${single_output}" "[+] Printing volume mount points for ${pod_name}" "single-pod path"
assert_contains "${single_output}" "Host Mount Point: ${host_path}" "single-pod path"

# Report successful completion after both interaction paths pass their assertions.
echo "main-menu item 5 passed live integration testing for all-pods and single-pod paths"
