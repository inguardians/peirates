#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
cluster_name="${PEIRATES_POD_INFO_KIND_CLUSTER:-peirates-pod-info-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-pod-info-test"
pod_name="peirates-pod-info-target"
role_name="peirates-pod-info-reader"
config_file="$(mktemp /tmp/peirates-pod-info-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-pod-info-binary.XXXXXX)"

cleanup() {
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    rm -f "${config_file}" "${peirates_binary}"
}
trap cleanup EXIT INT TERM

for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
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

kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never \
    --labels=peirates-test=pod-info --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

run_main_menu_item() {
    local item="$1"
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- \
        /tmp/peirates -c -m "${item}"
}
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

echo "main-menu items 3 and 4 passed live integration testing in order"
