#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can discover pods and
# retrieve their full details when run from a pod with scoped Kubernetes access.
#
# The script tests:
# - Refusal to modify a pre-existing Kind cluster with the configured name.
# - Pod get/list authorization for the target pod's default service account.
# - Main-menu item 3 pod-name discovery against a live Kubernetes API.
# - Main-menu item 4 pod detail and label retrieval against that API.

# Exit on command errors, unset variables, and failures within pipelines.
set -euo pipefail

# Resolve repository paths and initialize isolated test resources and names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
cluster_name="${PEIRATES_POD_INFO_KIND_CLUSTER:-peirates-pod-info-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-pod-info-test"
pod_name="peirates-pod-info-target"
role_name="peirates-pod-info-reader"
config_file="$(mktemp /tmp/peirates-pod-info-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-pod-info-binary.XXXXXX)"
cluster_owned=false

# Remove resources created by this run without touching pre-existing clusters.
cleanup() {
    if [[ "${cluster_owned}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Confirm prerequisites and guard against reusing an existing cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the disposable cluster and grant the target pod read-only pod access.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_owned=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s
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

# Start the labeled target pod and wait until it is ready for live assertions.
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never \
    --labels=peirates-test=pod-info --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

# Build and install Peirates inside the target pod.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

# Execute one Peirates main-menu item inside the test pod.
run_main_menu_item() {
    local item="$1"
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- \
        /tmp/peirates -c -m "${item}"
}
# Assert that a menu action emitted an expected result marker.
assert_contains() {
    local output="$1" expected="$2" item="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "main-menu item ${item} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Exercise item 3 before item 4 so a failure cannot be hidden by the broader
# JSON retrieval performed by item 4.
list_output="$(run_main_menu_item 3 2>&1)"
assert_contains "${list_output}" "[+] Pod Name: ${pod_name}" "3"

details_output="$(run_main_menu_item 4 2>&1)"
assert_contains "${details_output}" '"kind": "List"' "4"
assert_contains "${details_output}" "\"name\": \"${pod_name}\"" "4"
assert_contains "${details_output}" '"peirates-test": "pod-info"' "4"
assert_contains "${details_output}" "[+] Retrieving details for all pods was successful" "4"

# Report completion after ordered discovery and detail checks pass.
echo "main-menu items 3 and 4 passed live integration testing in order"
