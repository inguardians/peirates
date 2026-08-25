#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
cluster_name="${PEIRATES_EXEC_API_KIND_CLUSTER:-peirates-exec-api-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-exec-api-test"
runner_pod="peirates-exec-api-runner"
first_target_pod="peirates-exec-api-target-one"
second_target_pod="peirates-exec-api-target-two"
role_name="peirates-exec-api-runner"
config_file="$(mktemp /tmp/peirates-exec-api-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-exec-api-binary.XXXXXX)"
cluster_created=false

cleanup() {
    if [[ "${cluster_created}" == "true" ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
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
cluster_created=true

kubectl --context "${context}" create namespace "${namespace}"
# Peirates currently performs an `auth can-i exec pods` compatibility check
# before using the standard create permission on the pods/exec subresource.
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get,list --resource=pods
kubectl --context "${context}" -n "${namespace}" patch role "${role_name}" \
    --type=json \
    -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}}]'
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:default"

for permission in "get pods" "list pods" "exec pods" "create pods --subresource=exec"; do
    read -r -a permission_args <<<"${permission}"
    if [[ "$(kubectl --context "${context}" auth can-i "${permission_args[@]}" \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${permission}" >&2
        exit 1
    fi
done

for pod in "${runner_pod}" "${first_target_pod}" "${second_target_pod}"; do
    kubectl --context "${context}" -n "${namespace}" run "${pod}" \
        --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
done
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=120s

build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- chmod 0755 /tmp/peirates

specific_marker="/tmp/peirates-specific-pod-marker"
all_marker="/tmp/peirates-all-pods-marker"

# Numeric item 21: create a harmless marker in only the selected pod.
if ! specific_output="$(printf '1\nprintf peirates-specific > %s\n%s\n' \
    "${specific_marker}" "${first_target_pod}" | \
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${runner_pod}" -- \
        /tmp/peirates -c -m 21 2>&1)"; then
    echo "main-menu item 21 specific-pod execution failed" >&2
    printf '%s\n' "${specific_output}" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" -n "${namespace}" exec "${first_target_pod}" -- \
    cat "${specific_marker}")" != "peirates-specific" ]]; then
    echo "specific-pod execution did not create the expected marker in ${first_target_pod}" >&2
    printf '%s\n' "${specific_output}" >&2
    exit 1
fi
for pod in "${runner_pod}" "${second_target_pod}"; do
    if kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- \
        test -e "${specific_marker}" >/dev/null 2>&1; then
        echo "specific-pod execution unexpectedly created a marker in ${pod}" >&2
        printf '%s\n' "${specific_output}" >&2
        exit 1
    fi
done

# Canonical name: create and independently verify a marker in every running pod.
if ! all_output="$(printf '2\nprintf peirates-all > %s\n' "${all_marker}" | \
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${runner_pod}" -- \
        /tmp/peirates -c -m exec-via-api 2>&1)"; then
    echo "exec-via-api all-pods execution failed" >&2
    printf '%s\n' "${all_output}" >&2
    exit 1
fi
for pod in "${runner_pod}" "${first_target_pod}" "${second_target_pod}"; do
    if [[ "$(kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- \
        cat "${all_marker}")" != "peirates-all" ]]; then
        echo "all-pods execution did not create the expected marker in ${pod}" >&2
        printf '%s\n' "${all_output}" >&2
        exit 1
    fi
done

echo "main-menu item 21 passed specific-pod and all-pods live integration testing"
