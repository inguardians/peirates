#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster_name="${PEIRATES_NAMESPACE_KIND_CLUSTER:-peirates-namespace-integration}"
context="kind-${cluster_name}"
namespace="peirates-namespace-test"
target_namespace="peirates-namespace-target"
pod_name="peirates-namespace-test"
role_name="peirates-namespace-reader"
config_file="$(mktemp /tmp/peirates-namespace-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-namespace-binary.XXXXXX)"

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
kubectl --context "${context}" create namespace "${target_namespace}"
kubectl --context "${context}" create clusterrole "${role_name}" --verb=get,list --resource=namespaces
kubectl --context "${context}" create clusterrolebinding "${role_name}" \
    --clusterrole="${role_name}" --serviceaccount="${namespace}:default"
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" namespaces \
        --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} namespaces" >&2
        exit 1
    fi
done

kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

(cd "${root_dir}" && CGO_ENABLED=0 go build -o "${peirates_binary}" ./cmd/peirates)
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

run_namespace_menu() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c -m ns-menu
}
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "namespace ${action} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

list_output="$(printf '1\n' | run_namespace_menu 2>&1)"
assert_contains "${list_output}" "${namespace}" "list"
assert_contains "${list_output}" "${target_namespace}" "list"

# The submenu and switch action use separate stdin readers.
switch_output="$({ printf '2\n'; sleep 1; printf '%s\n' "${target_namespace}"; } | run_namespace_menu 2>&1)"
assert_contains "${switch_output}" "Enter namespace to switch to" "switch"
assert_contains "${switch_output}" "${target_namespace}" "switch"
if [[ "${switch_output}" == *"isn't a valid namespace"* ]]; then
    echo "namespace switch rejected the live target namespace" >&2
    printf '%s\n' "${switch_output}" >&2
    exit 1
fi

echo "all main-menu option 2 namespace actions passed live integration testing"
