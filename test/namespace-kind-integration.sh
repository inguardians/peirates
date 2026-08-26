#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can enumerate namespaces,
# switch to a namespace authorized through RBAC, and use that new namespace for
# subsequent pod discovery from an in-cluster service account.
#
# The script tests:
# - Namespace listing through the namespace module.
# - Switching from the starting namespace to a target namespace.
# - Target-scoped pod discovery after the namespace switch.
# - Rejection of false positives from namespace names and starting-namespace pods.

# Fail immediately on errors, unset variables, or failed pipeline commands.
set -euo pipefail

# Resolve repository paths, create isolated temporary files, and name fixtures.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_NAMESPACE_KIND_CLUSTER:-peirates-namespace-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-namespace-test"
target_namespace="peirates-namespace-target"
pod_name="peirates-namespace-test"
target_pod_name="peirates-namespace-target-only"
role_name="peirates-namespace-reader"
target_role_name="peirates-namespace-target-pod-reader"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_owned=false

# Remove the owned cluster and all temporary files on exit.
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
config_file="$(mktemp /tmp/peirates-namespace-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-namespace-binary.XXXXXX)"

# Check required tools and protect any existing cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the cluster, source and target namespaces, and scoped RBAC.
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
kubectl --context "${context}" create namespace "${target_namespace}"
kubectl --context "${context}" create clusterrole "${role_name}" --verb=get,list --resource=namespaces
kubectl --context "${context}" create clusterrolebinding "${role_name}" \
    --clusterrole="${role_name}" --serviceaccount="${namespace}:default"
kubectl --context "${context}" -n "${target_namespace}" create role "${target_role_name}" \
    --verb=get,list --resource=pods
kubectl --context "${context}" -n "${target_namespace}" create rolebinding "${target_role_name}" \
    --role="${target_role_name}" --serviceaccount="${namespace}:default"
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" namespaces \
        --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} namespaces" >&2
        exit 1
    fi
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" pods \
        --namespace="${target_namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} target-namespace pods" >&2
        exit 1
    fi
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" pods \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "no" ]]; then
        echo "default service account unexpectedly may ${verb} starting-namespace pods" >&2
        exit 1
    fi
done

# Start pods in both namespaces and wait until each is ready.
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${target_namespace}" run "${target_pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s
kubectl --context "${context}" -n "${target_namespace}" wait \
    --for=condition=Ready "pod/${target_pod_name}" --timeout=120s
if kubectl --context "${context}" -n "${namespace}" get pod "${target_pod_name}" >/dev/null 2>&1; then
    echo "target-only fixture unexpectedly exists in the starting namespace" >&2
    exit 1
fi

# Build Peirates and install it in the starting-namespace pod.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

# Run namespace actions and interactive sessions inside the test pod.
run_namespace_module() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c -m ns-menu
}
run_interactive_session() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -- \
        /tmp/peirates -c
}
# Assert expected and forbidden markers in captured output.
assert_contains() {
    local output="$1" expected="$2" action="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "namespace ${action} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}
assert_not_contains() {
    local output="$1" unexpected="$2" action="$3"
    if [[ "${output}" == *"${unexpected}"* ]]; then
        echo "namespace ${action} output unexpectedly contained: ${unexpected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}
target_pod_marker="[+] Pod Name: ${target_pod_name}"

# Verify the namespace listing action sees the target namespace.
list_output="$(printf '1\n' | run_namespace_module 2>&1)"
assert_contains "${list_output}" "${namespace}" "list"
assert_contains "${list_output}" "${target_namespace}" "list"

# A namespace listing and the starting pod name model the old false positive:
# neither is allowed to satisfy the target-only pod assertion.
ignored_switch_output="${namespace}
${target_namespace}
[+] Pod Name: ${pod_name}"
assert_not_contains "${ignored_switch_output}" "${target_pod_marker}" "ignored-switch regression check"
# The submenu and switch action use separate stdin readers.
# The main menu, namespace submenu, switch prompt, and pause use separate stdin
# readers. Keep the switch and the target-scoped pod listing in one process so
# get-pods observes the ServerInfo.Namespace mutation made by ns-menu.
if ! switch_output="$({ printf '2\n'; sleep 1; printf '2\n'; sleep 1; \
    printf '%s\n' "${target_namespace}"; sleep 1; printf 'continue\n'; sleep 1; \
    printf '3\n'; sleep 1; printf 'continue\n'; sleep 1; printf 'exit\n'; } | \
    run_interactive_session 2>&1)"; then
    echo "namespace switch interactive session failed" >&2
    printf '%s\n' "${switch_output}" >&2
    exit 1
fi
assert_contains "${switch_output}" "Enter namespace to switch to" "switch"
assert_contains "${switch_output}" "[+] Current namespace                 : ${target_namespace}" "switch"
if [[ "${switch_output}" == *"isn't a valid namespace"* ]]; then
    echo "namespace switch rejected the live target namespace" >&2
    printf '%s\n' "${switch_output}" >&2
    exit 1
fi
assert_contains "${switch_output}" "${target_pod_marker}" "post-switch pod list"
assert_not_contains "${switch_output}" "[+] Pod Name: ${pod_name}" "post-switch pod list"

# Report completion after listing, switching, and scoped discovery pass.
echo "all main-menu option 2 namespace actions passed live integration testing with a target-scoped follow-up"
