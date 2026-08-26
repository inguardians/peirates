#!/usr/bin/env bash
# This live integration test exercises Peirates' service-account menu from a
# pod in a disposable Kind cluster, verifying its interactive actions against
# a real Kubernetes service-account token and API context.
#
# The script tests:
# - Listing service accounts discovered from the running pod.
# - Switching to a discovered service account.
# - Adding an alternate account from a live token.
# - Exporting and importing service-account data.
# - Decoding a service-account token.
# - Displaying the token for a selected service account.

# Enable strict shell error handling for the integration workflow.
set -euo pipefail

# Resolve shared helpers and configure isolated cluster and temporary paths.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER:-peirates-service-account-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-service-account-test"
pod_name="peirates-service-account-test"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_owned=false
pod_token=""

# Remove the owned cluster and temporary files on all exit paths.
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
config_file="$(mktemp /tmp/peirates-service-account-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-service-account-binary.XXXXXX)"

# Check required tooling and refuse to modify a pre-existing cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the disposable cluster and a pod with a projected service-account token.
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
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

# Build Peirates for the node architecture and install it in the runner pod.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

# Load the projected token before capturing any Peirates output so every
# assertion failure, including early menu actions, can redact it.
pod_token="$(kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- \
    cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# Run the service-account submenu interactively inside the pod.
run_sa_menu() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c -m sa-menu
}
# Assert that each submenu action emits its expected output.
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "service-account ${action} output did not contain: $(redact_service_account_output "${expected}")" >&2
        redact_service_account_output "${output}" >&2
        exit 1
    fi
}

# Assertions inspect the unmodified output in memory; only diagnostics are
# transformed, so a failure can never disclose the disposable account token.
redact_service_account_output() {
    redact_service_account_token_output "$1" "${pod_token}"
}

# Delays prevent one of the submenu's several stdin readers from consuming a
# response intended for a later prompt.
list_output="$({ printf '1\n'; } | run_sa_menu 2>&1)"
assert_contains "${list_output}" "Available Service Accounts" "list"
assert_contains "${list_output}" "${namespace}:default" "list"

# Verify switching to the initially discovered account.
switch_output="$({ printf '2\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${switch_output}" "Selected ${namespace}:default" "switch"

# Verify adding the pod token under an alternate account name.
add_output="$({ printf '3\n'; sleep 1; printf '%s\n' "${pod_token}"; sleep 1; \
    printf 'alternate-live-account\n'; sleep 1; printf '2\n'; } | run_sa_menu 2>&1)"
assert_contains "${add_output}" "Switch to this service account" "add"

# Verify export output includes the discovered account metadata.
export_output="$({ printf '4\n'; } | run_sa_menu 2>&1)"
assert_contains "${export_output}" "\"Name\":\"${namespace}:default\"" "export"
assert_contains "${export_output}" "\"DiscoveryMethod\":\"Loaded at startup\"" "export"

# Import a synthetic account and confirm the menu accepts it.
import_json='[{"Name":"imported-live-account","Token":"aGVhZGVy.cGF5bG9hZA.signature","DiscoveryTime":"2026-01-01T00:00:00Z","DiscoveryMethod":"Live integration test"}]'
import_output="$({ printf '5\n'; sleep 1; printf '%s\n' "${import_json}"; } | run_sa_menu 2>&1)"
assert_contains "${import_output}" "Successfully imported service accounts" "import"

# Decode the live account token and verify its Kubernetes subject.
decode_output="$({ printf '6\n'; sleep 1; printf '2\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${decode_output}" "Payload:" "decode"
assert_contains "${decode_output}" "system:serviceaccount:${namespace}:default" "decode"

# Display the selected account and verify its complete token is shown.
display_output="$({ printf '7\n'; sleep 1; printf '0\n'; } | run_sa_menu 2>&1)"
assert_contains "${display_output}" "Service account ${namespace}:default is accessed with token" "display"
assert_contains "${display_output}" "${pod_token}" "display"

# Report completion after all service-account menu actions succeed.
echo "all main-menu option 1 service-account actions passed live integration testing"
