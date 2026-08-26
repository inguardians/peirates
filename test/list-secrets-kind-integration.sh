#!/usr/bin/env bash

# This live Kind integration test verifies that Peirates can enumerate Kubernetes
# Secrets through main-menu item 10 while respecting the pod's RBAC permissions.
#
# The script tests:
# - Access to opaque, TLS, and service-account-token Secret types.
# - Numeric and named aliases for the Secret-listing module.
# - Service account discovery from token Secrets.
# - Permission-denied handling without disclosing Secret names.

# Exit on errors, unset variables, and failed pipeline commands.
set -euo pipefail

# Resolve shared helpers and define the disposable cluster, fixture, and file names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_LIST_SECRETS_KIND_CLUSTER:-peirates-list-secrets-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-list-secrets-test"
allowed_pod="peirates-list-secrets-allowed"
denied_pod="peirates-list-secrets-denied"
denied_service_account="peirates-list-secrets-denied"
token_service_account="peirates-list-secrets-token"
opaque_secret="peirates-list-secrets-opaque"
tls_secret="peirates-list-secrets-tls"
token_secret="peirates-list-secrets-service-account-token"
role_name="peirates-list-secrets-reader"
kubeconfig_file=""
config_file=""
peirates_binary=""
tls_cert_file=""
tls_key_file=""
cluster_created=false

# Remove the disposable cluster and temporary files when the test exits.
cleanup() {
    trap '' INT TERM
    if [[ "${cluster_created}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${tls_cert_file}" "${tls_key_file}" \
        "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-list-secrets-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-list-secrets-binary.XXXXXX)"
tls_cert_file="$(mktemp /tmp/peirates-list-secrets-cert.XXXXXX.crt)"
tls_key_file="$(mktemp /tmp/peirates-list-secrets-key.XXXXXX.key)"

# Verify required tools are installed and protect any pre-existing cluster.
for required in kind kubectl docker go openssl timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create a disposable single-control-plane Kind cluster and test namespace.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_created=true
kind create cluster --name "${cluster_name}" --config "${config_file}" \
    --image "$(kind_node_image)" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

# Configure allowed and denied service accounts with namespace-scoped Secret RBAC.
kubectl --context "${context}" -n "${namespace}" create serviceaccount "${denied_service_account}"
kubectl --context "${context}" -n "${namespace}" create serviceaccount "${token_service_account}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get,list --resource=secrets
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:default"

# Confirm the service accounts have the expected get and list permissions.
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" secrets \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} secrets" >&2
        exit 1
    fi
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" secrets \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:${denied_service_account}")" != "no" ]]; then
        echo "denied service account unexpectedly may ${verb} secrets" >&2
        exit 1
    fi
done

# Create opaque, TLS, and service-account-token Secret fixtures.
kubectl --context "${context}" -n "${namespace}" create secret generic "${opaque_secret}" \
    --from-literal=fixture=peirates-disposable-opaque-value
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=peirates-list-secrets-live-cert' \
    -keyout "${tls_key_file}" -out "${tls_cert_file}" >/dev/null 2>&1
kubectl --context "${context}" -n "${namespace}" create secret tls "${tls_secret}" \
    --cert="${tls_cert_file}" --key="${tls_key_file}"
kubectl --context "${context}" -n "${namespace}" apply -f - <<TOKEN_SECRET
apiVersion: v1
kind: Secret
metadata:
  name: ${token_secret}
  annotations:
    kubernetes.io/service-account.name: ${token_service_account}
type: kubernetes.io/service-account-token
TOKEN_SECRET

# Start pods that exercise the allowed and denied service-account paths.
kubectl --context "${context}" -n "${namespace}" run "${allowed_pod}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" apply -f - <<DENIED_POD
apiVersion: v1
kind: Pod
metadata:
  name: ${denied_pod}
spec:
  serviceAccountName: ${denied_service_account}
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
DENIED_POD
for pod in "${allowed_pod}" "${denied_pod}"; do
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=condition=Ready "pod/${pod}" --timeout=120s
done

# Build Peirates for the Kind node architecture and install it in each test pod.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
for pod in "${allowed_pod}" "${denied_pod}"; do
    kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- chmod 0755 /tmp/peirates
done

# Define helpers to invoke a menu item and assert expected output fragments.
run_item() {
    local pod="$1" module="$2"
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- \
        /tmp/peirates -c -m "${module}"
}
assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "item 10 ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Verify the numeric item and named aliases enumerate every Secret fixture.
for module in 10 list-secrets get-secrets; do
    output="$(run_item "${allowed_pod}" "${module}" 2>&1)"
    assert_contains "${output}" "Attempting menu option ${module}" "${module}"
    for secret in "${opaque_secret}" "${tls_secret}" "${token_secret}"; do
        assert_contains "${output}" "[+] Secret found:" "${module}"
        assert_contains "${output}" "${secret}" "${module}"
    done
    assert_contains "${output}" "[+] Service account found:" "${module}"
    assert_contains "${output}" "${token_secret}" "${module}"
done

# Verify an unauthorized pod reports denial without revealing Secret names.
denied_output="$(run_item "${denied_pod}" 10 2>&1)"
assert_contains "${denied_output}" "Permission Denied" "denied"
for secret in "${opaque_secret}" "${tls_secret}" "${token_secret}"; do
    if [[ "${denied_output}" == *"${secret}"* ]]; then
        echo "denied item 10 output disclosed fixture Secret name: ${secret}" >&2
        printf '%s\n' "${denied_output}" >&2
        exit 1
    fi
done

# Report successful completion after every integration assertion passes.
echo "main-menu item 10 passed live integration testing for Secret types, aliases, and denial"
