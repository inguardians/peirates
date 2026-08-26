#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can discover mounted
# Kubernetes service-account tokens and use them in the expected order.
#
# The script tests:
# - kubectl-try-all attempts the denied runner and both authorized principals.
# - kubectl-try-all reports a result for every authorized principal.
# - kubectl-try-all-until-success stops after the first authorized principal.

# Enable strict shell error handling for the integration test.
set -euo pipefail

# Resolve repository helpers and create the test's isolated kubeconfig.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_KUBECTL_TRY_ALL_KIND_CLUSTER:-peirates-kubectl-try-all-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-kubectl-try-all-test"
runner_service_account="peirates-try-all-denied"
success_one_service_account="peirates-try-all-success-one"
success_two_service_account="peirates-try-all-success-two"
success_one_secret="peirates-success-one-token-live"
success_two_secret="peirates-success-two-token-live"
runner_pod="peirates-kubectl-try-all-runner"
fixture_configmap="peirates-kubectl-try-all-fixture"
fixture_value="peirates-live-try-all-result"
role_name="peirates-kubectl-try-all-reader"
kubeconfig_file=""
config_file=""
pod_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Remove the owned cluster, generated manifest, and temporary binaries on exit.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${pod_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-kubectl-try-all-kind.XXXXXX.yaml)"
pod_file="$(mktemp /tmp/peirates-kubectl-try-all-pod.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-kubectl-try-all-binary.XXXXXX)"

# Verify prerequisites and protect any cluster that predates this run.
for required in kind kubectl docker go sed timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create the disposable Kind cluster and test namespace.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

# Provision denied and authorized service accounts.
kubectl --context "${context}" create namespace "${namespace}"
for service_account in \
    "${runner_service_account}" \
    "${success_one_service_account}" \
    "${success_two_service_account}"; do
    kubectl --context "${context}" -n "${namespace}" create serviceaccount "${service_account}"
done

# Create the readable fixture and grant access only to successful principals.
kubectl --context "${context}" -n "${namespace}" create configmap "${fixture_configmap}" \
    --from-literal=marker="${fixture_value}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get --resource=configmaps --resource-name="${fixture_configmap}"
for service_account in "${success_one_service_account}" "${success_two_service_account}"; do
    kubectl --context "${context}" -n "${namespace}" create rolebinding \
        "${role_name}-${service_account}" --role="${role_name}" \
        --serviceaccount="${namespace}:${service_account}"
done

# These controller-populated Secrets hold real service-account credentials. The
# runner mounts them beneath a synthetic kubelet directory so Peirates discovers
# them in a deterministic order without being granted access to read Secrets.
for token_fixture in \
    "${success_one_secret}:${success_one_service_account}" \
    "${success_two_secret}:${success_two_service_account}"; do
    secret_name="${token_fixture%%:*}"
    service_account="${token_fixture#*:}"
    kubectl --context "${context}" -n "${namespace}" apply -f - <<TOKEN_SECRET
apiVersion: v1
kind: Secret
metadata:
  name: ${secret_name}
  annotations:
    kubernetes.io/service-account.name: ${service_account}
type: kubernetes.io/service-account-token
TOKEN_SECRET
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=jsonpath='{.data.token}' "secret/${secret_name}" --timeout=60s
done

# Confirm the runner is denied while both alternate principals are authorized.
if [[ "$(kubectl --context "${context}" auth can-i get \
    "configmap/${fixture_configmap}" --namespace="${namespace}" \
    --as="system:serviceaccount:${namespace}:${runner_service_account}")" != "no" ]]; then
    echo "denied runner service account unexpectedly may read the fixture" >&2
    exit 1
fi
for service_account in "${success_one_service_account}" "${success_two_service_account}"; do
    if [[ "$(kubectl --context "${context}" auth can-i get \
        "configmap/${fixture_configmap}" --namespace="${namespace}" \
        --as="system:serviceaccount:${namespace}:${service_account}")" != "yes" ]]; then
        echo "${service_account} was not authorized to read the fixture" >&2
        exit 1
    fi
done

# Generate the runner pod with deterministically ordered token mounts.
cat >"${pod_file}" <<RUNNER_POD
apiVersion: v1
kind: Pod
metadata:
  name: ${runner_pod}
  namespace: ${namespace}
spec:
  serviceAccountName: ${runner_service_account}
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: success-one-token
      mountPath: /var/lib/kubelet/pods/010-success-one/volumes/kubernetes.io~secret/${success_one_secret}
      readOnly: true
    - name: success-two-token
      mountPath: /var/lib/kubelet/pods/020-success-two/volumes/kubernetes.io~secret/${success_two_secret}
      readOnly: true
  volumes:
  - name: success-one-token
    secret:
      secretName: ${success_one_secret}
  - name: success-two-token
    secret:
      secretName: ${success_two_secret}
RUNNER_POD
# Start the runner and wait for its projected token volumes.
kubectl --context "${context}" apply -f "${pod_file}"
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${runner_pod}" --timeout=120s

# Build Peirates for the node architecture and install it in the runner.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- chmod 0755 /tmp/peirates

runner_name="${namespace}:${runner_service_account}"
success_one_name="${namespace}/${success_one_secret}"
success_two_name="${namespace}/${success_two_secret}"
kubectl_arguments="get configmap ${fixture_configmap} -o jsonpath={.data.marker}"

# Execute a named Peirates module inside the runner pod.
run_module() {
    local module="$1"
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- \
        /tmp/peirates -c -m "${module}"
}
# Redact live credentials before printing failed command output.
print_redacted() {
    printf '%s\n' "$1" | sed -E 's~eyJ[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2}~[REDACTED JWT]~g' >&2
}
# Assert required output, exclusions, ordering, and occurrence counts.
assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "${scenario} output did not contain: ${expected}" >&2
        print_redacted "${output}"
        exit 1
    fi
}
assert_not_contains() {
    local output="$1" unexpected="$2" scenario="$3"
    if [[ "${output}" == *"${unexpected}"* ]]; then
        echo "${scenario} unexpectedly attempted: ${unexpected}" >&2
        print_redacted "${output}"
        exit 1
    fi
}
assert_before() {
    local output="$1" first="$2" second="$3" scenario="$4" remainder
    assert_contains "${output}" "${first}" "${scenario}"
    remainder="${output#*"${first}"}"
    if [[ "${remainder}" != *"${second}"* ]]; then
        echo "${scenario} did not attempt ${second} after ${first}" >&2
        print_redacted "${output}"
        exit 1
    fi
}
count_occurrences() {
    local output="$1" needle="$2" remainder="${1}" count=0
    while [[ "${remainder}" == *"${needle}"* ]]; do
        remainder="${remainder#*"${needle}"}"
        count=$((count + 1))
    done
    printf '%s\n' "${count}"
}

# Verify kubectl-try-all attempts every discovered principal.
if ! try_all_output="$(run_module "kubectl-try-all ${kubectl_arguments}" 2>&1)"; then
    echo "kubectl-try-all live execution failed" >&2
    print_redacted "${try_all_output}"
    exit 1
fi
assert_before "${try_all_output}" "Trying ${runner_name}" \
    "Trying ${success_one_name}" "kubectl-try-all"
assert_before "${try_all_output}" "Trying ${success_one_name}" \
    "Trying ${success_two_name}" "kubectl-try-all"
assert_contains "${try_all_output}" "2 principals were successful" "kubectl-try-all"
if [[ "$(count_occurrences "${try_all_output}" "${fixture_value}")" != "2" ]]; then
    echo "kubectl-try-all did not report the fixture once for each authorized principal" >&2
    print_redacted "${try_all_output}"
    exit 1
fi

# Verify the until-success variant stops after its first authorized principal.
if ! until_success_output="$(run_module \
    "kubectl-try-all-until-success ${kubectl_arguments}" 2>&1)"; then
    echo "kubectl-try-all-until-success live execution failed" >&2
    print_redacted "${until_success_output}"
    exit 1
fi
assert_before "${until_success_output}" "Trying ${runner_name}" \
    "Trying ${success_one_name}" "kubectl-try-all-until-success"
assert_not_contains "${until_success_output}" "Trying ${success_two_name}" \
    "kubectl-try-all-until-success"
if [[ "$(count_occurrences "${until_success_output}" "${fixture_value}")" != "1" ]]; then
    echo "kubectl-try-all-until-success did not report exactly its first successful result" >&2
    print_redacted "${until_success_output}"
    exit 1
fi

# Report completion after both iteration behaviors are proven.
echo "kubectl-try-all tried every principal, and kubectl-try-all-until-success stopped at the first success"
