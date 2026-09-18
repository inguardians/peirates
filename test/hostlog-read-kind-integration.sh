#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can perform one bounded
# host-file read through a writable node /var/log mount and the kubelet /logs/
# endpoint exposed through the Kubernetes API server's nodes/proxy route.
#
# It tests:
# - numeric, canonical, and alias dispatch through a real static Peirates binary
# - exact reads of a synthetic marker outside node /var/log
# - cleanup of every temporary host-log symlink on success and request failure
# - authorization denial before mutation when get nodes/proxy is absent
# - local preflight failure for the same hostPath mounted read-only
# - preservation of marker metadata, Kubernetes objects, Pod readiness, and API health

# Stop immediately on setup, command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define isolated cluster, fixture, and RBAC names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_HOSTLOG_READ_KIND_CLUSTER:-peirates-hostlog-read-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-hostlog-read-test"
reader_service_account="peirates-hostlog-reader"
denied_service_account="peirates-hostlog-denied"
proxy_role="peirates-hostlog-node-proxy"
proxy_binding="peirates-hostlog-node-proxy"
reader_pod="peirates-hostlog-reader"
denied_pod="peirates-hostlog-denied"
readonly_pod="peirates-hostlog-readonly"
hostlog_mount="/var/log"
link_prefix=".peirates-hostlog-"
write_probe=".peirates-hostlog-live-write-probe"
marker_path="/tmp/peirates-hostlog-read-marker"
marker_value="peirates-hostlog-read-exact-marker"
missing_target="/tmp/peirates-hostlog-read-missing"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only the proven-owned cluster and this run's private temporary files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-hostlog-read-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-hostlog-read-binary.XXXXXX)"

# Verify required tools, serialize this cluster name, and fail closed if it exists.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create one disposable node with the legacy kubelet /logs/ file handler enabled.
# There are no Kind extraMounts, so later hostPath volumes reach only this node
# container and never a workstation or CI-host filesystem path.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    apiVersion: kubelet.config.k8s.io/v1beta1
    kind: KubeletConfiguration
    enableDebuggingHandlers: true
    enableSystemLogHandler: true
    enableSystemLogQuery: false
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"

# Grant only get nodes/proxy to the positive service account. The denied
# service account intentionally receives no RBAC grant.
kubectl --context "${context}" -n "${namespace}" create serviceaccount \
    "${reader_service_account}"
kubectl --context "${context}" -n "${namespace}" create serviceaccount \
    "${denied_service_account}"
kubectl --context "${context}" apply -f - <<RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${proxy_role}
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
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
  name: ${reader_service_account}
  namespace: ${namespace}
RBAC

# Verify the deliberately narrow positive grant and the denied control before
# giving either identity access to the test workload.
reader_identity="system:serviceaccount:${namespace}:${reader_service_account}"
denied_identity="system:serviceaccount:${namespace}:${denied_service_account}"
if [[ "$(kubectl --context "${context}" auth can-i get nodes --subresource=proxy --as="${reader_identity}")" != yes ]]; then
    echo "host-log reader service account lacks get nodes/proxy" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i get nodes --as="${reader_identity}")" != no ]]; then
    echo "host-log reader unexpectedly may get nodes" >&2
    exit 1
fi
for permission in "list secrets" "create pods"; do
    read -r verb resource <<<"${permission}"
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" "${resource}" \
        --namespace="${namespace}" --as="${reader_identity}")" != no ]]; then
        echo "host-log reader unexpectedly may ${verb} ${resource}" >&2
        exit 1
    fi
done
if [[ "$(kubectl --context "${context}" auth can-i get nodes --subresource=proxy --as="${denied_identity}")" != no ]]; then
    echo "denied service account unexpectedly may get nodes/proxy" >&2
    exit 1
fi

# Create writable, denied-RBAC, and read-only fixtures. Each receives NODE_NAME
# from the downward API so the action does not need node-list permission.
kubectl --context "${context}" -n "${namespace}" apply -f - <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${reader_pod}
spec:
  serviceAccountName: ${reader_service_account}
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
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-logs
      mountPath: ${hostlog_mount}
  volumes:
  - name: node-logs
    hostPath:
      path: /var/log
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${denied_pod}
spec:
  serviceAccountName: ${denied_service_account}
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
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-logs
      mountPath: ${hostlog_mount}
  volumes:
  - name: node-logs
    hostPath:
      path: /var/log
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${readonly_pod}
spec:
  serviceAccountName: ${reader_service_account}
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
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-logs
      mountPath: ${hostlog_mount}
      readOnly: true
  volumes:
  - name: node-logs
    hostPath:
      path: /var/log
      type: Directory
PODS
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=180s

# Build one architecture-matched static binary and install it with operator
# credentials. No workload identity receives pods/exec permission.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
for pod in "${reader_pod}" "${denied_pod}" "${readonly_pod}"; do
    kubectl --context "${context}" -n "${namespace}" cp -c runner \
        "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -c runner -- \
        chmod 0755 /tmp/peirates
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -c runner -- \
        test -s /var/run/secrets/kubernetes.io/serviceaccount/token
    observed_node="$(kubectl --context "${context}" -n "${namespace}" exec \
        "${pod}" -c runner -- printenv NODE_NAME)"
    if [[ "${observed_node}" != "${node_name}" ]]; then
        echo "${pod} NODE_NAME was ${observed_node}, expected ${node_name}" >&2
        exit 1
    fi
done

# Establish the mount boundary independently and prove that only the read-only
# fixture rejects a write to the disposable node's /var/log. Kind's staged bind
# mount can hide /var/log from mountinfo Root, so the same-path destination
# exercises the narrowly scoped fallback used for that runtime representation.
node_log_identity="$(docker exec "${node_name}" stat -c '%d:%i' /var/log)"
for pod in "${reader_pod}" "${denied_pod}" "${readonly_pod}"; do
    pod_log_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
        "${pod}" -c runner -- stat -c '%d:%i' "${hostlog_mount}")"
    if [[ "${pod_log_identity}" != "${node_log_identity}" ]]; then
        echo "${pod} does not mount the disposable node /var/log" >&2
        exit 1
    fi
done
kubectl --context "${context}" -n "${namespace}" exec "${reader_pod}" -c runner -- \
    sh -c "printf probe > '${hostlog_mount}/${write_probe}'"
docker exec "${node_name}" test -f "/var/log/${write_probe}"
kubectl --context "${context}" -n "${namespace}" exec "${reader_pod}" -c runner -- \
    rm -f -- "${hostlog_mount}/${write_probe}"
docker exec "${node_name}" test ! -e "/var/log/${write_probe}"
if kubectl --context "${context}" -n "${namespace}" exec "${readonly_pod}" -c runner -- \
    sh -c "printf probe > '${hostlog_mount}/${write_probe}'" 2>/dev/null; then
    echo "read-only host-log fixture unexpectedly accepted a write" >&2
    exit 1
fi
docker exec "${node_name}" test ! -e "/var/log/${write_probe}"

# Create one synthetic target outside /var/log and record its complete identity.
# The ordinary path beneath /var/log is absent, so only symlink traversal can
# make this marker reachable through the kubelet log file server.
docker exec "${node_name}" sh -c \
    "umask 022; printf '%s' '${marker_value}' > '${marker_path}'; chmod 0644 '${marker_path}'"
docker exec "${node_name}" rm -f -- "${missing_target}"
docker exec "${node_name}" sh -c \
    "test ! -e '/var/log${marker_path}' && test ! -L '/var/log${marker_path}'"
marker_stat_before="$(docker exec "${node_name}" stat -c '%d:%i:%f:%u:%g:%s' "${marker_path}")"
marker_hash_before="$(docker exec "${node_name}" sha256sum "${marker_path}" | awk '{print $1}')"
for pod in "${reader_pod}" "${denied_pod}" "${readonly_pod}"; do
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -c runner -- \
        test ! -e "${marker_path}"
done

# Prove the requested kubelet configuration and endpoint before Peirates runs.
for setting in \
    'enableDebuggingHandlers: true' \
    'enableSystemLogHandler: true' \
    'enableSystemLogQuery: false'; do
    if ! docker exec "${node_name}" grep -Fxq "${setting}" /var/lib/kubelet/config.yaml; then
        echo "disposable kubelet configuration lacks: ${setting}" >&2
        exit 1
    fi
done
kubectl --context "${context}" get --raw \
    "/api/v1/nodes/${node_name}/proxy/logs/" >/dev/null

# Define external assertions for the test-owned link prefix, marker, health,
# and exact public command output.
assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "host-log ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

assert_no_temp_links() {
    local leftovers
    leftovers="$(docker exec "${node_name}" find /var/log -maxdepth 1 \
        -name "${link_prefix}*" -print)"
    if [[ -n "${leftovers}" ]]; then
        echo "temporary host-log paths remain on the disposable node" >&2
        printf '%s\n' "${leftovers}" >&2
        exit 1
    fi
}

assert_marker_unchanged() {
    local marker_stat marker_hash
    marker_stat="$(docker exec "${node_name}" stat -c '%d:%i:%f:%u:%g:%s' "${marker_path}")"
    marker_hash="$(docker exec "${node_name}" sha256sum "${marker_path}" | awk '{print $1}')"
    if [[ "${marker_stat}" != "${marker_stat_before}" || "${marker_hash}" != "${marker_hash_before}" ]]; then
        echo "synthetic host target changed during host-log read" >&2
        printf 'before=%s/%s after=%s/%s\n' \
            "${marker_stat_before}" "${marker_hash_before}" "${marker_stat}" "${marker_hash}" >&2
        exit 1
    fi
    docker exec "${node_name}" sh -c \
        "test ! -e '/var/log${marker_path}' && test ! -L '/var/log${marker_path}'"
}

run_hostlog_read() {
    local pod="$1" module="$2" target="$3"
    printf '\n\n%s\n' "${target}" | timeout 90s \
        kubectl --context "${context}" -n "${namespace}" exec -i "${pod}" -c runner -- \
        /tmp/peirates -c -m "${module}" 2>&1
}

assert_successful_read() {
    local output="$1" module="$2" content cleanup_path cleanup_name
    assert_contains "${output}" "Attempting menu option ${module}" "${module} dispatch"
    assert_contains "${output}" "Mounted host-log path [auto-detect]: " "${module} mount prompt"
    assert_contains "${output}" "Kubernetes node name [${node_name}]: " "${module} node prompt"
    assert_contains "${output}" "Absolute host target path: " "${module} target prompt"
    assert_contains "${output}" "Kubelet /logs/ API proxy preflight succeeded." "${module} preflight"
    assert_contains "${output}" "Selected host-log mount: ${hostlog_mount} (node path /var/log)" \
        "${module} selected mount"
    assert_contains "${output}" "Host file content follows (treat as sensitive):" \
        "${module} content header"

    content="${output##*Host file content follows (treat as sensitive):$'\n'}"
    if [[ "${content}" != "${marker_value}" ]]; then
        echo "host-log ${module} did not return the exact synthetic marker bytes" >&2
        printf 'content=%q\n' "${content}" >&2
        exit 1
    fi

    mapfile -t cleanup_paths < <(sed -n \
        's/^Temporary host-log symlink removed: //p' <<<"${output}")
    if [[ "${#cleanup_paths[@]}" != 1 ]]; then
        echo "host-log ${module} did not report exactly one removed symlink" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
    cleanup_path="${cleanup_paths[0]}"
    if [[ ! "${cleanup_path}" =~ ^${hostlog_mount}/\.peirates-hostlog-[0-9a-f]{32}$ ]]; then
        echo "host-log ${module} reported an unexpected cleanup path: ${cleanup_path}" >&2
        exit 1
    fi
    cleanup_name="${cleanup_path##*/}"
    docker exec "${node_name}" sh -c \
        "test ! -e '/var/log/${cleanup_name}' && test ! -L '/var/log/${cleanup_name}'"
    assert_no_temp_links
    assert_marker_unchanged
}

assert_no_temp_links
kubernetes_before="$({
    kubectl --context "${context}" -n "${namespace}" get \
        pod,service,configmap,secret,serviceaccount,role,rolebinding,job,cronjob \
        -o name --ignore-not-found
    kubectl --context "${context}" get \
        "clusterrole/${proxy_role}" "clusterrolebinding/${proxy_binding}" -o name
} | LC_ALL=C sort)"

# Exercise every supported dispatch form and verify exact content and cleanup.
for module in 33 hostlog-symlink-read hostlog-read; do
    positive_output="$(run_hostlog_read "${reader_pod}" "${module}" "${marker_path}")"
    assert_successful_read "${positive_output}" "${module}"
done

# Authorization denial must occur during endpoint preflight, before any host
# symlink is created. Synthetic marker contents must not appear in diagnostics.
denied_output="$(run_hostlog_read "${denied_pod}" hostlog-symlink-read "${marker_path}")"
assert_contains "${denied_output}" \
    "probe kubelet log endpoint before filesystem mutation: authorization denied for get access to nodes/proxy" \
    "denied-RBAC preflight"
if [[ "${denied_output}" == *"${marker_value}"* ||
    "${denied_output}" == *"Temporary host-log symlink removed:"* ]]; then
    echo "denied-RBAC path read content or reached filesystem mutation" >&2
    printf '%s\n' "${denied_output}" >&2
    exit 1
fi
assert_no_temp_links
assert_marker_unchanged

# A read-only mount must fail local qualification without reading the marker or
# creating a temporary path.
readonly_output="$(run_hostlog_read "${readonly_pod}" hostlog-symlink-read "${marker_path}")"
assert_contains "${readonly_output}" "no writable direct host-log mount passed qualification" \
    "read-only mount"
if [[ "${readonly_output}" == *"${marker_value}"* ||
    "${readonly_output}" == *"Temporary host-log symlink removed:"* ]]; then
    echo "read-only path read content or reported filesystem mutation" >&2
    printf '%s\n' "${readonly_output}" >&2
    exit 1
fi
assert_no_temp_links
assert_marker_unchanged

# A missing target forces a kubelet read error after link creation. The
# temporary link must still be removed and the marker must remain unchanged.
missing_output="$(run_hostlog_read "${reader_pod}" hostlog-symlink-read "${missing_target}")"
assert_contains "${missing_output}" "read host file through kubelet log endpoint:" \
    "missing-target cleanup"
if [[ "${missing_output}" == *"${marker_value}"* ]]; then
    echo "missing-target diagnostics exposed the marker" >&2
    exit 1
fi
assert_no_temp_links
assert_marker_unchanged

# Prove the action changed no Kubernetes inventory and left every fixture and
# the Kubernetes API healthy.
kubernetes_after="$({
    kubectl --context "${context}" -n "${namespace}" get \
        pod,service,configmap,secret,serviceaccount,role,rolebinding,job,cronjob \
        -o name --ignore-not-found
    kubectl --context "${context}" get \
        "clusterrole/${proxy_role}" "clusterrolebinding/${proxy_binding}" -o name
} | LC_ALL=C sort)"
if [[ "${kubernetes_after}" != "${kubernetes_before}" ]]; then
    echo "Kubernetes resources changed during host-log symlink reads" >&2
    diff <(printf '%s\n' "${kubernetes_before}") <(printf '%s\n' "${kubernetes_after}") >&2 || true
    exit 1
fi
for pod in "${reader_pod}" "${denied_pod}" "${readonly_pod}"; do
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=condition=Ready "pod/${pod}" --timeout=10s
done
if [[ "$(kubectl --context "${context}" get --raw /readyz)" != ok ]]; then
    echo "Kubernetes API readiness check failed after host-log reads" >&2
    exit 1
fi
kubectl --context "${context}" get --raw \
    "/api/v1/nodes/${node_name}/proxy/healthz" | grep -Fxq ok

echo "main-menu item 33 passed live bounded host-log symlink read integration testing"
