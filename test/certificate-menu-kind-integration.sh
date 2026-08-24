#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster_name="${PEIRATES_CERTIFICATE_KIND_CLUSTER:-peirates-certificate-integration}"
node_name="${cluster_name}-control-plane"
expected_identity="system:node:${node_name}"
config_file="$(mktemp /tmp/peirates-certificate-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-certificate-binary.XXXXXX)"

cleanup() {
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    rm -f "${config_file}" "${peirates_binary}"
}
trap cleanup EXIT INT TERM

for required in kind docker go timeout; do
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

(cd "${root_dir}" && CGO_ENABLED=0 go build -o "${peirates_binary}" ./cmd/peirates)
docker cp "${peirates_binary}" "${node_name}:/peirates"
docker exec "${node_name}" chmod 0755 /peirates

run_certificate_menu() {
    timeout 90s docker exec -i "${node_name}" /peirates -c -m cert-menu
}
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "certificate-menu ${action} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

list_output="$(printf 'list\n' | run_certificate_menu 2>&1)"
assert_contains "${list_output}" "Found Kubelet certificate and secret key: ${expected_identity}" "list"
assert_contains "${list_output}" "Available Client Certificate/Key Pairs" "list"
assert_contains "${list_output}" "[0] ${expected_identity}" "list"

# The certificate menu and switch action use separate stdin readers.
switch_output="$({ printf 'switch\n'; sleep 1; printf '0\n'; } | run_certificate_menu 2>&1)"
assert_contains "${switch_output}" "Available Client Certificate/Key Pairs" "switch"
assert_contains "${switch_output}" "[0] ${expected_identity}" "switch"
assert_contains "${switch_output}" "Selected ${expected_identity}" "switch"

echo "main-menu item 9 passed live node integration testing for list and switch"
