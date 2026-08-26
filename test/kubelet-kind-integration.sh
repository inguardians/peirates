#!/usr/bin/env bash
# This integration test verifies that Peirates can discover pods and execute a
# command through an anonymously accessible kubelet in a disposable Kind cluster.
#
# The script tests:
# - Anonymous kubelet pod listing and command execution through the Go integration test.
# - The compiled Peirates CLI's exec-via-api module from inside a test pod.
# - The minimum service-account permissions needed to discover nodes and access pods.

# Exit on errors, unset variables, and failures hidden within pipelines.
set -euo pipefail

# SECURITY: This test deliberately enables anonymous kubelet pod listing and exec.
# The setting is confined to a uniquely named, disposable Kind cluster. Never point
# this script at an existing or shared cluster.
# Resolve repository paths and define isolated test resource names and files.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
cluster_name="${PEIRATES_KUBELET_KIND_CLUSTER:-peirates-kubelet-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-kubelet-test"
node_lister_role="peirates-kubelet-test-node-lister"
node_lister_binding="peirates-kubelet-test-node-lister"
pod_reader_role="peirates-kubelet-test-pod-reader"
pod_reader_binding="peirates-kubelet-test-pod-reader"
pod_exec_role="peirates-kubelet-test-pod-exec"
pod_exec_binding="peirates-kubelet-test-pod-exec"
pod_name="kubelet-exec-target"
config_file="$(mktemp /tmp/peirates-kubelet-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-kubelet-binary.XXXXXX)"
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

# Check prerequisites and refuse to modify an existing Kind cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done

if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Write the intentionally vulnerable kubelet configuration.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        anonymous-auth: "true"
        authorization-mode: "AlwaysAllow"
        read-only-port: "10255"
CONFIG

# Create the cluster and grant minimal node, pod-read, and pod-exec permissions.
cluster_owned=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

kubectl --context "${context}" create clusterrole "${node_lister_role}" \
    --verb=get,list --resource=nodes
kubectl --context "${context}" create clusterrolebinding "${node_lister_binding}" \
    --clusterrole="${node_lister_role}" --serviceaccount="${namespace}:default"
kubectl --context "${context}" -n "${namespace}" create role "${pod_reader_role}" \
    --verb=get,list,exec --resource=pods
kubectl --context "${context}" -n "${namespace}" create rolebinding "${pod_reader_binding}" \
    --role="${pod_reader_role}" --serviceaccount="${namespace}:default"
kubectl --context "${context}" -n "${namespace}" create role "${pod_exec_role}" \
    --verb=create --resource=pods/exec
kubectl --context "${context}" -n "${namespace}" create rolebinding "${pod_exec_binding}" \
    --role="${pod_exec_role}" --serviceaccount="${namespace}:default"

# Verify the default service account has exactly the intended access.
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" nodes \
        --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} nodes" >&2
        exit 1
    fi
done
if [[ "$(kubectl --context "${context}" auth can-i list pods -n "${namespace}" \
    --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
    echo "default service account was not authorized to list pods" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i create pods --subresource=exec -n "${namespace}" \
    --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
    echo "default service account was not authorized to create pods/exec" >&2
    exit 1
fi

# Start the target pod and discover its container and node address.
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait --for=condition=Ready "pod/${pod_name}" --timeout=120s
container_name="$(kubectl --context "${context}" -n "${namespace}" get pod "${pod_name}" -o jsonpath='{.spec.containers[0].name}')"
if [[ -z "${container_name}" ]]; then
    echo "could not determine target container name from the disposable pod" >&2
    exit 1
fi

node_ip="$(kubectl --context "${context}" get node "${cluster_name}-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "${node_ip}" ]]; then
    echo "could not determine disposable Kind node IP" >&2
    exit 1
fi

# Run the tagged Go test against the anonymous kubelet endpoints.
PEIRATES_KUBELET_NODE_IP="${node_ip}" \
PEIRATES_KUBELET_NAMESPACE="${namespace}" \
PEIRATES_KUBELET_POD="${pod_name}" \
PEIRATES_KUBELET_CONTAINER="${container_name}" \
    go test -tags=kubelet_integration ./internal/app -run '^TestAnonymousKubeletPodListingAndExec$' -count=1 -v

# Install Peirates in the target pod and exercise exec-via-api live.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp \
    "${peirates_binary}" "${pod_name}:/tmp/peirates" -c "${container_name}"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c "${container_name}" -- chmod 0755 /tmp/peirates

peirates_output="$(printf '2\nid\n' | timeout 90s kubectl --context "${context}" -n "${namespace}" \
    exec -i "${pod_name}" -c "${container_name}" -- /tmp/peirates -c -m exec-via-api 2>&1)"
printf '%s\n' "${peirates_output}"
if [[ "${peirates_output}" != *"uid="* ]]; then
    echo "Peirates exec-via-api did not return id output from the running pods" >&2
    exit 1
fi
