#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
cluster_name="${PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER:-peirates-service-account-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-service-account-test"
pod_name="peirates-service-account-test"
config_file="$(mktemp /tmp/peirates-service-account-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-service-account-binary.XXXXXX)"

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
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

run_sa_menu() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c -m sa-menu
}
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "service-account ${action} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Delays prevent one of the submenu's several stdin readers from consuming a
# response intended for a later prompt.
list_output="$({ printf '1\n'; } | run_sa_menu 2>&1)"
assert_contains "${list_output}" "Available Service Accounts" "list"
assert_contains "${list_output}" "${namespace}:default" "list"

switch_output="$({ printf '2\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${switch_output}" "Selected ${namespace}:default" "switch"

pod_token="$(kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- \
    cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
add_output="$({ printf '3\n'; sleep 1; printf '%s\n' "${pod_token}"; sleep 1; \
    printf 'alternate-live-account\n'; sleep 1; printf '2\n'; } | run_sa_menu 2>&1)"
assert_contains "${add_output}" "Switch to this service account" "add"

export_output="$({ printf '4\n'; } | run_sa_menu 2>&1)"
assert_contains "${export_output}" "\"Name\":\"${namespace}:default\"" "export"
assert_contains "${export_output}" "\"DiscoveryMethod\":\"Loaded at startup\"" "export"

import_json='[{"Name":"imported-live-account","Token":"aGVhZGVy.cGF5bG9hZA.signature","DiscoveryTime":"2026-01-01T00:00:00Z","DiscoveryMethod":"Live integration test"}]'
import_output="$({ printf '5\n'; sleep 1; printf '%s\n' "${import_json}"; } | run_sa_menu 2>&1)"
assert_contains "${import_output}" "Successfully imported service accounts" "import"

decode_output="$({ printf '6\n'; sleep 1; printf '2\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${decode_output}" "Payload:" "decode"
assert_contains "${decode_output}" "system:serviceaccount:${namespace}:default" "decode"

display_output="$({ printf '7\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${display_output}" "Service account ${namespace}:default is accessed with token" "display"
assert_contains "${display_output}" "${pod_token}" "display"

echo "all main-menu option 1 service-account actions passed live integration testing"
