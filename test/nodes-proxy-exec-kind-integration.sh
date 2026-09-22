#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates reviews every stored
# service-account token and uses an explicitly selected non-active token to
# execute one bounded command through a direct kubelet WebSocket GET request.
#
# The script tests:
# - a denied active token, an allowed stored token, and another denied stored token
# - node-specific get nodes/proxy without create nodes/proxy or pods/exec
# - verified kubelet TLS and direct port 10250 access
# - deterministic stored-token and running-container selection
# - independent marker verification after WebSocket command execution
# - denial and confirmation controls that create no marker
# - token and token-digest redaction plus claim-aware cluster cleanup

# Stop on command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define isolated cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_NODES_PROXY_EXEC_KIND_CLUSTER:-peirates-nodes-proxy-exec-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-nodes-proxy-exec-test"
runner_service_account="peirates-nodes-proxy-runner"
attacker_service_account="peirates-nodes-proxy-attacker"
stored_denied_service_account="peirates-nodes-proxy-stored-denied"
attacker_secret="peirates-attacker-token-live"
stored_denied_secret="peirates-stored-denied-token-live"
kubelet_ca_configmap="peirates-kubelet-serving-ca"
proxy_role="peirates-nodes-proxy-get"
proxy_binding="peirates-nodes-proxy-get"
runner_pod="peirates-nodes-proxy-runner"
target_pod="peirates-nodes-proxy-target"
target_container="target"
marker_path="/tmp/peirates-nodes-proxy-marker"
denied_marker_path="/tmp/peirates-nodes-proxy-denied-marker"
marker_value="peirates-nodes-proxy-exact-marker"
kubelet_ca_path="/var/run/peirates-kubelet-ca/ca.crt"
kubeconfig_file=""
config_file=""
pod_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only the proven-owned cluster and this run's temporary files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${pod_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-nodes-proxy-kind.XXXXXX.yaml)"
pod_file="$(mktemp /tmp/peirates-nodes-proxy-pods.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-nodes-proxy-binary.XXXXXX)"

# Verify tooling, serialize this cluster name, and protect existing clusters.
for required in kind kubectl docker go sed awk sha256sum timeout base64; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create a standard disposable Kind node. Default webhook token authentication
# and authorization are required; anonymous or AlwaysAllow kubelet modes are
# deliberately not enabled.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

# Create the denied active identity, one allowed alternate identity, and a
# second denied alternate identity.
for service_account in \
    "${runner_service_account}" \
    "${attacker_service_account}" \
    "${stored_denied_service_account}"; do
    kubectl --context "${context}" -n "${namespace}" create serviceaccount \
        "${service_account}"
done

# Grant only node-specific get nodes/proxy to the attacker token. The CREATE
# verb and pods/exec remain denied so the live result isolates GET semantics.
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
  name: ${attacker_service_account}
  namespace: ${namespace}
RBAC

runner_identity="system:serviceaccount:${namespace}:${runner_service_account}"
attacker_identity="system:serviceaccount:${namespace}:${attacker_service_account}"
stored_denied_identity="system:serviceaccount:${namespace}:${stored_denied_service_account}"
if [[ "$(kubectl --context "${context}" auth can-i get "nodes/${node_name}" \
    --subresource=proxy --as="${attacker_identity}")" != yes ]]; then
    echo "attacker service account lacks node-specific get nodes/proxy" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i create "nodes/${node_name}" \
    --subresource=proxy --as="${attacker_identity}")" != no ]]; then
    echo "attacker service account unexpectedly may create nodes/proxy" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i create pods \
    --subresource=exec -n "${namespace}" --as="${attacker_identity}")" != no ]]; then
    echo "attacker service account unexpectedly may create pods/exec" >&2
    exit 1
fi
for denied_identity in "${runner_identity}" "${stored_denied_identity}"; do
    if [[ "$(kubectl --context "${context}" auth can-i get "nodes/${node_name}" \
        --subresource=proxy --as="${denied_identity}")" != no ]]; then
        echo "denied service account unexpectedly may get nodes/proxy: ${denied_identity}" >&2
        exit 1
    fi
done

# Create controller-populated token Secrets. The runner mounts them under a
# synthetic kubelet directory so Peirates discovers them in deterministic
# order without the runner receiving API permission to read Secrets.
for token_fixture in \
    "${attacker_secret}:${attacker_service_account}" \
    "${stored_denied_secret}:${stored_denied_service_account}"; do
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

# Kind's kubelet serving certificate is not signed by the service-account CA.
# Publish only that public certificate into the runner so the direct endpoint
# is verified without granting the runner access to node files or credentials.
kubelet_serving_certificate="$(docker exec "${node_name}" \
    cat /var/lib/kubelet/pki/kubelet.crt)"
if [[ "${kubelet_serving_certificate}" != *"BEGIN CERTIFICATE"* ]]; then
    echo "could not read the disposable node kubelet serving certificate" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" create configmap \
    "${kubelet_ca_configmap}" --from-literal="ca.crt=${kubelet_serving_certificate}"

# Mount the alternate tokens into the denied runner and create one command
# target. NODE_NAME supplies an explicit, independently verified node default.
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
    - name: attacker-token
      mountPath: /var/lib/kubelet/pods/010-attacker/volumes/kubernetes.io~secret/${attacker_secret}
      readOnly: true
    - name: stored-denied-token
      mountPath: /var/lib/kubelet/pods/020-denied/volumes/kubernetes.io~secret/${stored_denied_secret}
      readOnly: true
    - name: kubelet-ca
      mountPath: /var/run/peirates-kubelet-ca
      readOnly: true
  volumes:
  - name: attacker-token
    secret:
      secretName: ${attacker_secret}
  - name: stored-denied-token
    secret:
      secretName: ${stored_denied_secret}
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

# Resolve the direct kubelet origin and establish fixture state independently.
node_ip="$(kubectl --context "${context}" get node "${node_name}" \
    -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "${node_ip}" ]]; then
    echo "could not determine the disposable node InternalIP" >&2
    exit 1
fi
kubelet_origin="https://${node_ip}:10250"
observed_node="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${runner_pod}" -c runner -- printenv NODE_NAME)"
if [[ "${observed_node}" != "${node_name}" ]]; then
    echo "runner NODE_NAME was ${observed_node}, expected ${node_name}" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" exec "${target_pod}" \
    -c "${target_container}" -- test ! -e "${marker_path}"
kubectl --context "${context}" -n "${namespace}" exec "${target_pod}" \
    -c "${target_container}" -- test ! -e "${denied_marker_path}"

# Build one node-architecture binary and install it using administrator
# credentials; the runner identity receives no pod-exec permission.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp -c runner \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -c runner -- \
    chmod 0755 /tmp/peirates

# Capture exact live token values only for negative leak assertions. Diagnostics
# pass through the shared redactor and never print these values.
runner_token="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${runner_pod}" -c runner -- \
    cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
attacker_token="$(kubectl --context "${context}" -n "${namespace}" get secret \
    "${attacker_secret}" -o jsonpath='{.data.token}' | base64 -d)"
stored_denied_token="$(kubectl --context "${context}" -n "${namespace}" get secret \
    "${stored_denied_secret}" -o jsonpath='{.data.token}' | base64 -d)"

print_redacted() {
    local output="$1" token digest
    for token in "${runner_token}" "${attacker_token}" "${stored_denied_token}"; do
        output="$(redact_service_account_token_output "${output}" "${token}")"
        digest="$(printf '%s' "${token}" | sha256sum | awk '{print $1}')"
        output="${output//${digest}/[REDACTED-TOKEN-DIGEST]}"
    done
    printf '%s\n' "${output}" >&2
}

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "nodes-proxy ${scenario} output did not contain: ${expected}" >&2
        print_redacted "${output}"
        exit 1
    fi
}

assert_no_credentials() {
    local output="$1" scenario="$2" token digest
    for token in "${runner_token}" "${attacker_token}" "${stored_denied_token}"; do
        digest="$(printf '%s' "${token}" | sha256sum | awk '{print $1}')"
        if [[ "${output}" == *"${token}"* || "${output}" == *"${digest}"* ]]; then
            echo "nodes-proxy ${scenario} output exposed a token or token digest" >&2
            print_redacted "${output}"
            exit 1
        fi
    done
}

run_module() {
    local input="$1" module="$2"
    printf '%s' "${input}" | timeout 90s \
        kubectl --context "${context}" -n "${namespace}" exec -i \
        "${runner_pod}" -c runner -- /tmp/peirates -c -m "${module}" 2>&1
}

# First run the numeric dispatch through read-only preflight, then stop at the
# target prompt. This proves all stored tokens were reviewed and supplies the
# exact target index without relying on Kind system-pod ordering.
discovery_input="$(printf '\n1\n%s\nca-file\n%s\n%s\n' \
    "${kubelet_origin}" "${kubelet_ca_path}" "${node_name}")"
discovery_input+=$'\n'
discovery_output="$(run_module "${discovery_input}" 34)"
runner_name="${namespace}:${runner_service_account}"
attacker_name="${namespace}/${attacker_secret}"
stored_denied_name="${namespace}/${stored_denied_secret}"
assert_contains "${discovery_output}" \
    "[0] name=\"${runner_name}\" method=\"Loaded at startup\" get nodes/proxy=denied create nodes/proxy=unchecked" \
    "active denied token"
assert_contains "${discovery_output}" \
    "[1] name=\"${attacker_name}\" method=\"pod secret harvested from node \" get nodes/proxy=allowed create nodes/proxy=denied" \
    "allowed stored token"
assert_contains "${discovery_output}" \
    "[2] name=\"${stored_denied_name}\" method=\"pod secret harvested from node \" get nodes/proxy=denied create nodes/proxy=unchecked" \
    "scan continued after success"
assert_no_credentials "${discovery_output}" "discovery"

target_index="$(sed -n \
    "s/^\[\([0-9][0-9]*\)\] ${namespace}\/${target_pod}\/${target_container} kind=regular node=${node_name}$/\1/p" \
    <<<"${discovery_output}")"
if [[ ! "${target_index}" =~ ^[0-9]+$ ]]; then
    echo "could not resolve the target container index from Peirates output" >&2
    print_redacted "${discovery_output}"
    exit 1
fi

# A denied stored-token selection must stop before the kubelet origin prompt
# and must not create either marker.
denied_input="$(printf '\n0\n')"
denied_input+=$'\n'
denied_output="$(run_module "${denied_input}" nodes-proxy-exec)"
if [[ "${denied_output}" == *"Kubelet HTTPS origin:"* ]]; then
    echo "denied token selection reached direct kubelet configuration" >&2
    print_redacted "${denied_output}"
    exit 1
fi
assert_no_credentials "${denied_output}" "denied selection"
kubectl --context "${context}" -n "${namespace}" exec "${target_pod}" \
    -c "${target_container}" -- test ! -e "${denied_marker_path}"

# Incorrect final confirmation reaches no execution side effect.
denied_argv="[\"/bin/sh\",\"-c\",\"printf denied > ${denied_marker_path}\"]"
wrong_confirmation_input="$(printf '\n1\n%s\nca-file\n%s\n%s\n%s\n%s\nNO\n' \
    "${kubelet_origin}" "${kubelet_ca_path}" "${node_name}" \
    "${target_index}" "${denied_argv}")"
wrong_confirmation_input+=$'\n'
wrong_confirmation_output="$(run_module "${wrong_confirmation_input}" nodes-proxy-exec)"
assert_contains "${wrong_confirmation_output}" \
    "Type EXEC-VIA-NODES-PROXY-${node_name} to continue:" "confirmation prompt"
assert_no_credentials "${wrong_confirmation_output}" "wrong confirmation"
kubectl --context "${context}" -n "${namespace}" exec "${target_pod}" \
    -c "${target_container}" -- test ! -e "${denied_marker_path}"

# Select the non-active allowed token and execute one bounded marker command.
positive_argv="[\"/bin/sh\",\"-c\",\"printf '%s' '${marker_value}' > ${marker_path}\"]"
positive_input="$(printf '\n1\n%s\nca-file\n%s\n%s\n%s\n%s\nEXEC-VIA-NODES-PROXY-%s\n' \
    "${kubelet_origin}" "${kubelet_ca_path}" "${node_name}" \
    "${target_index}" "${positive_argv}" "${node_name}")"
positive_input+=$'\n'
positive_output="$(run_module "${positive_input}" nodes-proxy-exec)"
assert_contains "${positive_output}" "Selected token: [1] ${attacker_name}" \
    "selected non-active token"
assert_contains "${positive_output}" "Kubelet TLS: verified" "verified kubelet TLS"
assert_contains "${positive_output}" "Result classification: confirmed-get-only-exec" \
    "GET-only execution"
assert_no_credentials "${positive_output}" "positive execution"

# Verify the command side effect independently with administrator credentials.
observed_marker="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${target_pod}" -c "${target_container}" -- cat "${marker_path}")"
if [[ "${observed_marker}" != "${marker_value}" ]]; then
    echo "direct kubelet execution did not create the exact marker" >&2
    print_redacted "${positive_output}"
    exit 1
fi

# Reassert the narrow RBAC contract and cluster health after successful exec.
if [[ "$(kubectl --context "${context}" auth can-i create "nodes/${node_name}" \
    --subresource=proxy --as="${attacker_identity}")" != no ||
    "$(kubectl --context "${context}" auth can-i create pods --subresource=exec \
    -n "${namespace}" --as="${attacker_identity}")" != no ]]; then
    echo "attacker permissions expanded during nodes-proxy execution" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${runner_pod}" "pod/${target_pod}" --timeout=10s
if [[ "$(kubectl --context "${context}" get --raw /readyz)" != ok ]]; then
    echo "Kubernetes API readiness failed after nodes-proxy execution" >&2
    exit 1
fi

echo "menu item 34 reviewed every stored token and confirmed GET-only direct kubelet execution"
