#!/usr/bin/env bash
# This manual integration test provisions an isolated Kind cluster with an
# intentionally vulnerable kubelet so Peirates kubelet access can be exercised.
#
# The script tests:
# - Safe creation and cleanup of a dedicated Kind cluster and kubeconfig.
# - Anonymous access to the kubelet read-only and HTTPS execution endpoints.
# - Node-listing RBAC for the target namespace's default service account.
# - Discovery of the target pod, container, and node connection details.

# Exit on errors, unset variables, and failed pipeline commands.
set -euo pipefail

# SECURITY: This creates an intentionally vulnerable kubelet for local testing.
# It must only be used as a disposable Kind cluster on an isolated workstation.
# Define the dedicated cluster resources and track setup ownership and state.
cluster_name="${PEIRATES_KUBELET_MANUAL_CLUSTER:-peirates-kubelet-manual}"
context="kind-${cluster_name}"
namespace="peirates-kubelet-manual"
node_lister_role="peirates-kubelet-manual-node-lister"
node_lister_binding="peirates-kubelet-manual-node-lister"
pod_name="kubelet-manual-target"
config_file=""
kubeconfig_file="${PEIRATES_KUBELET_MANUAL_KUBECONFIG:-}"
kubeconfig_owned=false
setup_complete=false
cluster_owned=false

# Clean up only resources created by this invocation.
cleanup() {
    if [[ "${cluster_owned}" == true && "${setup_complete}" != true ]]; then
        echo "setup did not complete; deleting partial cluster ${cluster_name}" >&2
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}"
    if [[ "${kubeconfig_owned}" == true && "${setup_complete}" != true ]]; then
        rm -f "${kubeconfig_file}"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Create a secure temporary kubeconfig when one was not supplied.
if [[ -z "${kubeconfig_file}" ]]; then
    kubeconfig_file="$(mktemp /tmp/peirates-kubelet-manual-kubeconfig.XXXXXX)"
    kubeconfig_owned=true
elif [[ -e "${kubeconfig_file}" || -L "${kubeconfig_file}" ]]; then
    echo "refusing to overwrite existing manual kubeconfig ${kubeconfig_file}" >&2
    exit 1
elif ! (umask 077; set -o noclobber; : >"${kubeconfig_file}") 2>/dev/null; then
    echo "refusing to overwrite existing manual kubeconfig ${kubeconfig_file}" >&2
    exit 1
fi
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-kubelet-manual.XXXXXX.yaml)"

# Verify tooling and refuse to modify a pre-existing cluster.
for required in kind kubectl docker; do
    command -v "${required}" >/dev/null || {
        echo "missing required command: ${required}" >&2
        exit 1
    }
done

if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    echo "choose another name with PEIRATES_KUBELET_MANUAL_CLUSTER" >&2
    exit 1
fi

# Write a Kind configuration that enables the deliberately vulnerable kubelet.
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

# Create the cluster, namespace, and minimal node-listing RBAC.
cluster_owned=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" create clusterrole "${node_lister_role}" \
    --verb=get,list --resource=nodes
kubectl --context "${context}" create clusterrolebinding "${node_lister_binding}" \
    --clusterrole="${node_lister_role}" --serviceaccount="${namespace}:default"
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" nodes \
        --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} nodes" >&2
        exit 1
    fi
done

# Start the target pod and collect its container and node address.
kubectl --context "${context}" -n "${namespace}" run "${pod_name}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

container_name="$(kubectl --context "${context}" -n "${namespace}" get pod "${pod_name}" -o jsonpath='{.spec.containers[0].name}')"
node_ip="$(kubectl --context "${context}" get node "${cluster_name}-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "${container_name}" || -z "${node_ip}" ]]; then
    echo "could not determine target container name or node IP" >&2
    exit 1
fi

# Prepare cleanup instructions for either owned or caller-supplied kubeconfigs.
setup_complete=true
printf -v kubeconfig_command_path '%q' "${kubeconfig_file}"
if [[ "${kubeconfig_owned}" == true ]]; then
    kubeconfig_cleanup_command="  rm -f ${kubeconfig_command_path}"
else
    kubeconfig_cleanup_command="  # Retain the caller-supplied kubeconfig: ${kubeconfig_file}"
fi

# Print connection details, manual test commands, and the security warning.
cat <<INFO

The intentionally vulnerable manual test cluster is ready and will remain running.

Cluster:   ${cluster_name}
Context:   ${context}
Kubeconfig: ${kubeconfig_file}
Node IP:   ${node_ip}
Target:    ${namespace}/${pod_name}/${container_name}
RBAC:      system:serviceaccount:${namespace}:default may get and list nodes

List pods anonymously through the read-only kubelet port:
  curl -fsS http://${node_ip}:10255/pods

Execute id anonymously through the HTTPS kubelet port:
  curl -ksS -X POST 'https://${node_ip}:10250/run/${namespace}/${pod_name}/${container_name}/?cmd=id'

Inspect the target through Kubernetes:
  KUBECONFIG=${kubeconfig_command_path} kubectl --context ${context} -n ${namespace} exec ${pod_name} -c ${container_name} -- id

Delete the cluster when finished:
  KUBECONFIG=${kubeconfig_command_path} kind delete cluster --name ${cluster_name}
${kubeconfig_cleanup_command}

WARNING: anonymous authentication, AlwaysAllow authorization, and the read-only
kubelet port are intentionally enabled. Do not expose or reuse this cluster.
INFO
