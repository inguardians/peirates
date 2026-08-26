#!/usr/bin/env bash

# This live Kind integration test verifies that Peirates discovers the control-plane
# node's kubelet client certificate and can use the certificate menu interactively.
#
# The script tests:
# - Listing the kubelet certificate and secret key with the expected node identity.
# - Displaying the discovered certificate in the available certificate/key pairs.
# - Switching to the discovered certificate through the interactive menu.

# Enable strict shell error handling.
set -euo pipefail

# Resolve repository paths and create isolated files and cluster identifiers.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
cluster_name="${PEIRATES_CERTIFICATE_KIND_CLUSTER:-peirates-certificate-integration}"
node_name="${cluster_name}-control-plane"
expected_identity="system:node:${node_name}"
config_file="$(mktemp /tmp/peirates-certificate-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-certificate-binary.XXXXXX)"
cluster_owned=false

# Delete only the cluster created by this run and remove temporary files.
cleanup() {
    if [[ "${cluster_owned}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Check prerequisites and refuse to alter a cluster that already exists.
for required in kind docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Define and create the disposable single-node Kind cluster.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_owned=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s

# Build Peirates for the node architecture and install it in the node container.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
docker cp "${peirates_binary}" "${node_name}:/peirates"
docker exec "${node_name}" chmod 0755 /peirates

# Run the certificate submenu in the Kind node with a fixed timeout.
run_certificate_menu() {
    timeout 90s docker exec -i "${node_name}" /peirates -c -m cert-menu
}
# Fail with captured output when an expected menu marker is absent.
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "certificate-menu ${action} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Verify certificate discovery and listing output.
list_output="$(printf 'list\n' | run_certificate_menu 2>&1)"
assert_contains "${list_output}" "Found Kubelet certificate and secret key: ${expected_identity}" "list"
assert_contains "${list_output}" "Available Client Certificate/Key Pairs" "list"
assert_contains "${list_output}" "[0] ${expected_identity}" "list"

# The certificate menu and switch action use separate stdin readers.
switch_output="$({ printf 'switch\n'; sleep 1; printf '0\n'; } | run_certificate_menu 2>&1)"
assert_contains "${switch_output}" "Available Client Certificate/Key Pairs" "switch"
assert_contains "${switch_output}" "[0] ${expected_identity}" "switch"
assert_contains "${switch_output}" "Selected ${expected_identity}" "switch"

# Report completion after both certificate-menu paths succeed.
echo "main-menu item 9 passed live node integration testing for list and switch"
