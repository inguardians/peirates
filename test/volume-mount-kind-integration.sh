#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster_name="${PEIRATES_VOLUME_MOUNT_KIND_CLUSTER:-peirates-volume-mount-integration}"
context="kind-${cluster_name}"
namespace="peirates-volume-mount-test"
pod_name="peirates-volume-mount-target"
role_name="peirates-volume-mount-reader"
host_path="/tmp/peirates-observable-host-volume"
config_file="$(mktemp /tmp/peirates-volume-mount-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-volume-mount-binary.XXXXXX)"

cleanup() {
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
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
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=get,list --resource=pods
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:default"
for verb in get list; do
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" pods \
        --namespace="${namespace}" --as="system:serviceaccount:${namespace}:default")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} pods" >&2
        exit 1
    fi
done

kubectl --context "${context}" -n "${namespace}" apply -f - <<POD
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  labels:
    peirates-test: volume-mount
spec:
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: observable-host-volume
      mountPath: /mnt/observable-host-volume
  volumes:
  - name: observable-host-volume
    hostPath:
      path: ${host_path}
      type: DirectoryOrCreate
POD
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

(cd "${root_dir}" && CGO_ENABLED=0 go build -o "${peirates_binary}" ./cmd/peirates)
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -- chmod 0755 /tmp/peirates

run_volume_mount_item() {
    local input="$1"
    printf '%s' "${input}" | timeout 90s kubectl --context "${context}" -n "${namespace}" \
        exec -i "${pod_name}" -- /tmp/peirates -c -m find-volume-mounts
}
assert_contains() {
    local output="$1" expected="$2" path_name="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "main-menu item 5 ${path_name} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

all_output="$(run_volume_mount_item $'all\n' 2>&1)"
assert_contains "${all_output}" "Host Mount Point: ${host_path} found for pod ${pod_name}" "all-pods path"

single_output="$(run_volume_mount_item $'single\n'"${pod_name}"$'\n' 2>&1)"
assert_contains "${single_output}" "[+] Printing volume mount points for ${pod_name}" "single-pod path"
assert_contains "${single_output}" "Host Mount Point: ${host_path}" "single-pod path"

echo "main-menu item 5 passed live integration testing for all-pods and single-pod paths"
