#!/usr/bin/env bash
# This manual Kind test creates a disposable cluster and starts Peirates with
# the nodes-proxy-exec module attached to the operator's terminal.
#
# The script tests:
# - a denied active token, an allowed stored token, and a later denied token
# - node-specific get nodes/proxy without create nodes/proxy or pods/exec
# - verified direct kubelet TLS using the disposable node's serving certificate
# - explicit operator selection of the stored token and running container
# - one operator-confirmed WebSocket GET command and an independent marker check
# - claim-aware cleanup of only the cluster created by this invocation

# Stop on command, pipeline, or unset-variable failures.
set -euo pipefail

# Keep this process in the foreground so kubectl can attach the worker Pod to
# the controlling terminal. The ordinary Kind EXIT and signal traps still
# clean up the proven-owned cluster when the interactive session ends.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
fixture_prefix="peirates-nodes-proxy-manual"
cluster_name="${PEIRATES_NODES_PROXY_EXEC_MANUAL_CLUSTER:-${fixture_prefix}-cluster}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="${fixture_prefix}"
runner_service_account="${fixture_prefix}-runner"
allowed_service_account="${fixture_prefix}-allowed"
denied_service_account="${fixture_prefix}-denied"
allowed_secret="${fixture_prefix}-allowed-token-live"
denied_secret="${fixture_prefix}-denied-token-live"
kubelet_ca_configmap="${fixture_prefix}-kubelet-serving-ca"
proxy_role="${fixture_prefix}-get"
proxy_binding="${fixture_prefix}-get"
runner_pod="${fixture_prefix}-runner"
target_pod="${fixture_prefix}-target"
target_container="target"
marker_path="/tmp/${fixture_prefix}-marker"
marker_value="${fixture_prefix}-success"
kubelet_ca_path="/var/run/peirates-kubelet-ca/ca.crt"
kubeconfig_file=""
config_file=""
pod_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only this invocation's proven-owned cluster and temporary files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${pod_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

# Refuse to create anything unless an operator terminal is available.
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "nodes-proxy manual test requires an interactive terminal" >&2
    exit 1
fi

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp "/tmp/${fixture_prefix}-kind.XXXXXX.yaml")"
pod_file="$(mktemp "/tmp/${fixture_prefix}-pods.XXXXXX.yaml")"
peirates_binary="$(mktemp "/tmp/${fixture_prefix}-binary.XXXXXX")"

# Verify tooling, serialize the dedicated cluster name, and fail closed if it
# already exists or Kind cannot enumerate clusters.
for required in kind kubectl docker go; do
    command -v "${required}" >/dev/null || {
        echo "missing required command: ${required}" >&2
        exit 1
    }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Use an ordinary authenticated and webhook-authorized Kind kubelet. The test
# does not enable anonymous auth, AlwaysAllow, or the read-only kubelet port.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

# Create three identities. Only the alternate stored token receives the narrow
# node-specific nodes/proxy GET grant used by the feature.
for service_account in \
    "${runner_service_account}" \
    "${allowed_service_account}" \
    "${denied_service_account}"; do
    kubectl --context "${context}" -n "${namespace}" create serviceaccount \
        "${service_account}"
done

kubectl --context "${context}" apply -f - <<RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${proxy_role}
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  resourceNames: ["${node_name}"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${proxy_binding}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${proxy_role}
subjects:
- kind: ServiceAccount
  name: ${allowed_service_account}
  namespace: ${namespace}
RBAC

runner_identity="system:serviceaccount:${namespace}:${runner_service_account}"
allowed_identity="system:serviceaccount:${namespace}:${allowed_service_account}"
denied_identity="system:serviceaccount:${namespace}:${denied_service_account}"
if [[ "$(kubectl --context "${context}" auth can-i get "nodes/${node_name}" \
    --subresource=proxy --as="${allowed_identity}")" != yes ]]; then
    echo "allowed service account lacks node-specific get nodes/proxy" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i create "nodes/${node_name}" \
    --subresource=proxy --as="${allowed_identity}")" != no ]]; then
    echo "allowed service account unexpectedly may create nodes/proxy" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i create pods \
    --subresource=exec -n "${namespace}" --as="${allowed_identity}")" != no ]]; then
    echo "allowed service account unexpectedly may create pods/exec" >&2
    exit 1
fi
for identity in "${runner_identity}" "${denied_identity}"; do
    if [[ "$(kubectl --context "${context}" auth can-i get "nodes/${node_name}" \
        --subresource=proxy --as="${identity}")" != no ]]; then
        echo "denied identity unexpectedly may get nodes/proxy: ${identity}" >&2
        exit 1
    fi
done

# Create controller-populated legacy token Secrets for deterministic alternate
# credentials, then expose only the public kubelet serving certificate as the
# direct endpoint trust anchor.
for token_fixture in \
    "${allowed_secret}:${allowed_service_account}" \
    "${denied_secret}:${denied_service_account}"; do
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

kubelet_serving_certificate="$(docker exec "${node_name}" \
    cat /var/lib/kubelet/pki/kubelet.crt)"
if [[ "${kubelet_serving_certificate}" != *"BEGIN CERTIFICATE"* ]]; then
    echo "could not read the disposable node kubelet serving certificate" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" create configmap \
    "${kubelet_ca_configmap}" --from-literal="ca.crt=${kubelet_serving_certificate}"

# Mount both alternate tokens where Peirates' existing node-filesystem gatherer
# finds them in stable order. The runner itself remains non-root with all Linux
# capabilities dropped.
cat >"${pod_file}" <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${runner_pod}
  namespace: ${namespace}
spec:
  serviceAccountName: ${runner_service_account}
  containers:
  - name: runner
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
    securityContext:
      runAsUser: 65534
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: allowed-token
      mountPath: /var/lib/kubelet/pods/010-allowed/volumes/kubernetes.io~secret/${allowed_secret}
      readOnly: true
    - name: denied-token
      mountPath: /var/lib/kubelet/pods/020-denied/volumes/kubernetes.io~secret/${denied_secret}
      readOnly: true
    - name: kubelet-ca
      mountPath: /var/run/peirates-kubelet-ca
      readOnly: true
  volumes:
  - name: allowed-token
    secret:
      secretName: ${allowed_secret}
  - name: denied-token
    secret:
      secretName: ${denied_secret}
  - name: kubelet-ca
    configMap:
      name: ${kubelet_ca_configmap}
---
apiVersion: v1
kind: Pod
metadata:
  name: ${target_pod}
  namespace: ${namespace}
spec:
  containers:
  - name: ${target_container}
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
PODS
kubectl --context "${context}" apply -f "${pod_file}"
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=180s

# Resolve the direct origin, install a node-architecture binary, and prove the
# marker is absent before handing control to the operator.
node_ip="$(kubectl --context "${context}" get node "${node_name}" \
    -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "${node_ip}" ]]; then
    echo "could not determine the disposable node InternalIP" >&2
    exit 1
fi
kubelet_origin="https://${node_ip}:10250"
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp -c runner \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -c runner -- \
    chmod 0755 /tmp/peirates
kubectl --context "${context}" -n "${namespace}" exec "${target_pod}" \
    -c "${target_container}" -- test ! -e "${marker_path}"

# Show the exact safe path through the prompts. The running-container index is
# deliberately selected from Peirates' displayed list rather than inferred.
cat <<INSTRUCTIONS

The disposable nodes/proxy interactive test is ready.

Peirates will review these stored entries:
  [0] active runner token: expected get nodes/proxy=denied
  [1] ${namespace}/${allowed_secret}: expected get nodes/proxy=allowed
  [2] ${namespace}/${denied_secret}: expected get nodes/proxy=denied

Enter the following values when prompted:

  Kubernetes node name:
    press ENTER to accept ${node_name}
  Stored token index:
    1
  Kubelet HTTPS origin:
    ${kubelet_origin}
  Kubelet TLS mode:
    ca-file
  Kubelet CA file:
    ${kubelet_ca_path}
  Kubelet TLS server name:
    ${node_name}
  Running container index:
    choose the row for ${namespace}/${target_pod}/${target_container}
  Command argv JSON:
    ["/bin/sh","-c","printf '%s' '${marker_value}' > ${marker_path}"]
  Final confirmation:
    EXEC-VIA-NODES-PROXY-${node_name}

The cluster will be deleted automatically after Peirates exits. Press Ctrl-C
to cancel safely; cancellation will also run ownership-checked cleanup.

INSTRUCTIONS

# Attach Peirates directly to the operator terminal. Module errors are rendered
# by Peirates; the independent marker assertion below is the test oracle.
kubectl --context "${context}" -n "${namespace}" exec -it \
    "${runner_pod}" -c runner -- /tmp/peirates -c -m nodes-proxy-exec

observed_marker="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${target_pod}" -c "${target_container}" -- cat "${marker_path}" 2>/dev/null || true)"
if [[ "${observed_marker}" != "${marker_value}" ]]; then
    echo "interactive nodes/proxy test did not create the expected marker" >&2
    echo "expected the documented command to write ${marker_path}" >&2
    exit 1
fi

# Reassert the narrow authorization contract and cluster health independently
# before the EXIT trap removes the fixture.
if [[ "$(kubectl --context "${context}" auth can-i create "nodes/${node_name}" \
    --subresource=proxy --as="${allowed_identity}")" != no ||
    "$(kubectl --context "${context}" auth can-i create pods --subresource=exec \
    -n "${namespace}" --as="${allowed_identity}")" != no ]]; then
    echo "allowed identity permissions expanded during the interactive test" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" get --raw /readyz)" != ok ]]; then
    echo "Kubernetes API readiness failed after the interactive test" >&2
    exit 1
fi

echo "interactive nodes-proxy-exec test passed; cleaning up ${cluster_name}"
