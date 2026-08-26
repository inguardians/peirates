#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can import a Kubernetes
# service-account token from a Secret while operating with deliberately narrow
# Secret permissions inside a disposable cluster.
#
# The script tests:
# - Main-menu item 11 imports and retains a decoded service-account token.
# - The secret-to-sa and get-secret module aliases perform the same import.
# - Non-service-account-token Secrets are rejected with the expected message.
# - The test identity can get Secrets but cannot list them.

# Exit on errors, unset variables, and failed pipeline components.
set -euo pipefail

# Resolve repository paths and define the disposable cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
cluster_name="${PEIRATES_SECRET_TO_SA_KIND_CLUSTER:-peirates-secret-to-sa-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-secret-to-sa-test"
pod_name="peirates-secret-to-sa-runner"
token_service_account="peirates-secret-to-sa-fixture"
token_secret="peirates-secret-to-sa-token"
opaque_secret="peirates-secret-to-sa-opaque"
role_name="peirates-secret-to-sa-reader"
config_file="$(mktemp /tmp/peirates-secret-to-sa-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-secret-to-sa-binary.XXXXXX)"
cluster_created=false
fixture_token=""

# Delete the owned cluster and temporary files on exit.
cleanup() {
    if [[ "${cluster_created}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Verify prerequisites and refuse to modify a pre-existing cluster.
for required in kind kubectl docker go base64 timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the cluster, namespace, service account, and get-only Secret RBAC.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_created=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" create serviceaccount "${token_service_account}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get --resource=secrets
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:default"
if [[ "$(kubectl --context "${context}" auth can-i get secrets \
    --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
    echo "default service account was not authorized to get secrets" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i list secrets \
    --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "no" ]]; then
    echo "default service account unexpectedly may list secrets" >&2
    exit 1
fi

# Create token and opaque Secret fixtures for success and rejection paths.
kubectl --context "${context}" -n "${namespace}" apply -f - <<TOKEN_SECRET
apiVersion: v1
kind: Secret
metadata:
  name: ${token_secret}
  annotations:
    kubernetes.io/service-account.name: ${token_service_account}
type: kubernetes.io/service-account-token
TOKEN_SECRET
kubectl --context "${context}" -n "${namespace}" create secret generic "${opaque_secret}" \
    --from-literal=fixture=not-a-service-account-token

# The token controller fills manually created service-account-token Secrets
# asynchronously. Keep the decoded token only in memory so it never reaches a
# temporary file or successful test output.
for _ in $(seq 1 60); do
    encoded_token="$(kubectl --context "${context}" -n "${namespace}" get secret "${token_secret}" \
        -o jsonpath='{.data.token}')"
    if [[ -n "${encoded_token}" ]]; then
        fixture_token="$(printf '%s' "${encoded_token}" | base64 --decode)"
        break
    fi
    sleep 1
done
if [[ -z "${fixture_token}" ]]; then
    echo "service-account-token Secret was not populated" >&2
    exit 1
fi

# Start the runner pod and wait for its projected credentials.
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

# Build Peirates and install it in the runner pod.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

# Redact credentials and report captured output on assertion failures.
redact_output() {
    local output="$1"
    printf '%s\n' "${output//${fixture_token}/[REDACTED SERVICE ACCOUNT TOKEN]}"
}
fail_output() {
    local message="$1" output="$2"
    echo "${message}" >&2
    redact_output "${output}" >&2
    exit 1
}
# Assert expected messages and decoded-token evidence.
assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        fail_output "item 11 ${scenario} output did not contain: ${expected}" "${output}"
    fi
}
assert_token_was_decoded() {
    local output="$1" scenario="$2"
    if [[ "${output}" != *"${fixture_token}"* ]]; then
        fail_output "item 11 ${scenario} did not decode the fixture token" "${output}"
    fi
}
# Execute a named Secret-import module inside the runner pod.
run_module() {
    local module="$1" secret="$2"
    printf '%s\n' "${secret}" | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c -m "${module}"
}

# Drive the numeric main-menu item and then list accounts in the same process.
# This proves the decoded token was retained by AddNewServiceAccount rather
# than merely fetched and printed.
if ! interactive_output="$({ printf '11\n'; sleep 1; printf '%s\n' "${token_secret}"; sleep 1; \
    printf 'continue\n'; sleep 1; printf 'listsa\n'; sleep 1; printf 'continue\n'; sleep 1; \
    printf 'exit\n'; } | \
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c 2>&1)"; then
    fail_output "item 11 interactive session failed" "${interactive_output}"
fi
assert_contains "${interactive_output}" "[+] Saved ${token_secret} //" "interactive"
assert_token_was_decoded "${interactive_output}" "interactive"
assert_contains "${interactive_output}" "Available Service Accounts:" "interactive"
assert_contains "${interactive_output}" "${token_secret}" "interactive account list"

# Verify both supported aliases import the same service-account token.
for module in secret-to-sa get-secret; do
    if ! output="$(run_module "${module}" "${token_secret}" 2>&1)"; then
        fail_output "item 11 ${module} execution failed" "${output}"
    fi
    assert_contains "${output}" "Attempting menu option ${module}" "${module}"
    assert_contains "${output}" "[+] Saved ${token_secret} //" "${module}"
    assert_token_was_decoded "${output}" "${module}"
done

# Verify non-service-account Secrets are rejected cleanly.
if ! opaque_output="$(run_module secret-to-sa "${opaque_secret}" 2>&1)"; then
    fail_output "item 11 non-token Secret execution failed" "${opaque_output}"
fi
assert_contains "${opaque_output}" "This secret is not a service account token" "non-token Secret"

# Report completion after numeric, alias, and rejection paths succeed.
echo "main-menu item 11 passed live integration testing for token import, aliases, and type rejection"
