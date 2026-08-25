#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
cluster_name="${PEIRATES_ATTACK_HOSTPATH_KIND_CLUSTER:-peirates-attack-hostpath-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-attack-hostpath-test"
runner_pod="peirates-attack-hostpath-runner"
role_name="peirates-attack-hostpath-pod-manager"
marker_path="/peirates-item20-disposable-marker"
marker_value="peirates-item20-mounted-node-root"
callback_ip="127.0.0.1"
callback_port="65535"
config_file="$(mktemp /tmp/peirates-attack-hostpath-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-attack-hostpath-binary.XXXXXX)"
output_file="$(mktemp /tmp/peirates-attack-hostpath-output.XXXXXX)"
cluster_created=false

cleanup() {
    if [[ "${cluster_created}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${output_file}"
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
cluster_created=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" apply -f - <<RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${role_name}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${role_name}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${role_name}
subjects:
- kind: ServiceAccount
  name: default
  namespace: ${namespace}
RBAC

service_account="system:serviceaccount:${namespace}:default"
for permission in "get pods" "list pods" "create pods" "delete pods" "create pods/exec"; do
    read -r verb resource <<<"${permission}"
    if [[ "$(kubectl --context "${context}" auth can-i "${verb}" "${resource}" \
        --namespace="${namespace}" --as="${service_account}")" != "yes" ]]; then
        echo "default service account was not authorized to ${verb} ${resource}" >&2
        exit 1
    fi
done
if [[ "$(kubectl --context "${context}" auth can-i list secrets \
    --namespace="${namespace}" --as="${service_account}")" != "no" ]]; then
    echo "default service account unexpectedly may list secrets" >&2
    exit 1
fi

kubectl --context "${context}" -n "${namespace}" run "${runner_pod}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${runner_pod}" --timeout=120s

# The marker and callback cron line exist only in the disposable Kind node
# container. No path from the Docker host is mounted into this cluster.
if docker exec "${node_name}" awk '$2 ~ /:FFFF$/ && $4 == "0A" { found=1 } END { exit found ? 0 : 1 }' /proc/net/tcp /proc/net/tcp6; then
    echo "callback port ${callback_port} is unexpectedly listening inside ${node_name}" >&2
    exit 1
fi
docker exec "${node_name}" sh -c "printf '%s\\n' '${marker_value}' > '${marker_path}'"
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- chmod 0755 /tmp/peirates

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "item 20 ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

find_attack_pod() {
    local attack_pod="" attempt
    for attempt in $(seq 1 150); do
        attack_pod="$(kubectl --context "${context}" -n "${namespace}" get pods \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
            | grep '^attack-pod-' | head -n 1 || true)"
        if [[ -n "${attack_pod}" ]]; then
            printf '%s\n' "${attack_pod}"
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_item() {
    local module="$1" attack_pod host_path mounted_marker output

    : >"${output_file}"
    (
        printf '%s\n%s\n' "${callback_ip}" "${callback_port}" \
            | timeout 120s kubectl --context "${context}" -n "${namespace}" exec -i "${runner_pod}" -- \
                /tmp/peirates -c -m "${module}"
    ) >"${output_file}" 2>&1 &
    local module_pid=$!

    if ! attack_pod="$(find_attack_pod)"; then
        wait "${module_pid}" || true
        echo "item 20 ${module} did not create an attack pod" >&2
        sed -n '1,240p' "${output_file}" >&2
        exit 1
    fi

    host_path="$(kubectl --context "${context}" -n "${namespace}" get "pod/${attack_pod}" \
        -o jsonpath='{.spec.volumes[?(@.name=="mount-fsroot-into-slashroot")].hostPath.path}')"
    if [[ "${host_path}" != "/" ]]; then
        echo "item 20 ${module} attack pod hostPath was ${host_path}, not /" >&2
        exit 1
    fi
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=condition=Ready "pod/${attack_pod}" --timeout=60s
    mounted_marker="$(kubectl --context "${context}" -n "${namespace}" exec "${attack_pod}" -- \
        cat "/root${marker_path}")"
    if [[ "${mounted_marker}" != "${marker_value}" ]]; then
        echo "item 20 ${module} did not expose the disposable node marker through /root" >&2
        exit 1
    fi

    if ! wait "${module_pid}"; then
        echo "item 20 ${module} failed" >&2
        sed -n '1,240p' "${output_file}" >&2
        exit 1
    fi
    output="$(<"${output_file}")"
    assert_contains "${output}" "Attempting menu option ${module}" "${module}"
    assert_contains "${output}" "[+] Netcat callback added sucessfully." "${module}"
    assert_contains "${output}" "[+] Removing attack pod." "${module}"
    if kubectl --context "${context}" -n "${namespace}" get "pod/${attack_pod}" >/dev/null 2>&1; then
        echo "item 20 ${module} left attack pod ${attack_pod} behind" >&2
        exit 1
    fi
}

# Exercise the numbered menu item, canonical module name, and a historical alias.
for module in 20 attack-pod-hostpath-mount attack-hostpath-mount; do
    run_item "${module}"
done

cron_contents="$(docker exec "${node_name}" sh -c 'test -f /etc/crontab && cat /etc/crontab')"
assert_contains "${cron_contents}" "${callback_ip}" "node crontab callback IP"
assert_contains "${cron_contents}" "${callback_port}" "node crontab callback port"
assert_contains "${cron_contents}" "python3 -c" "node crontab command"

echo "main-menu item 20 passed live integration testing for its numeric, canonical, and alias commands"
