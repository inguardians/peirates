#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can discover opaque,
# TLS, and service-account secrets from the Kubernetes node filesystem.
#
# It tests:
# - creation and node-side mounting of disposable opaque and TLS secrets
# - startup discovery of a projected service-account token
# - dispatch and execution of the nodefs-steal-secrets module
# - reporting and summary output for the secrets found on the node

# Exit on errors, unset variables, or failed pipeline commands.
set -euo pipefail

# Define repository paths, disposable resources, and test fixture values.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
cluster_name="${PEIRATES_NODEFS_SECRETS_KIND_CLUSTER:-peirates-nodefs-secrets-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-nodefs-secrets-test"
pod_name="peirates-nodefs-secrets-target"
secret_name="peirates-nodefs-fixture"
tls_secret_name="peirates-nodefs-tls-fixture"
service_account_name="peirates-nodefs-service-account"
fixture_value="peirates-disposable-nodefs-fixture"
config_file="$(mktemp /tmp/peirates-nodefs-secrets-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-nodefs-secrets-binary.XXXXXX)"
tls_cert_file="$(mktemp /tmp/peirates-nodefs-cert.XXXXXX.crt)"
tls_key_file="$(mktemp /tmp/peirates-nodefs-key.XXXXXX.key)"
cluster_created=false

# Remove the disposable cluster and temporary files when the test exits.
cleanup() {
    if [[ "${cluster_created}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${tls_cert_file}" "${tls_key_file}" \
        "${kubeconfig_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Verify required tools are installed and protect any same-named existing cluster.
for required in kind kubectl docker go openssl timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Write the minimal Kind configuration and create the disposable cluster.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_created=true
kind create cluster --name "${cluster_name}" --config "${config_file}" --wait 120s

# Create the namespace, service account, opaque secret, and TLS secret fixtures.
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" create serviceaccount "${service_account_name}"
kubectl --context "${context}" -n "${namespace}" create secret generic "${secret_name}" \
    --from-literal=fixture="${fixture_value}"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=peirates-nodefs-live-cert' \
    -keyout "${tls_key_file}" -out "${tls_cert_file}" >/dev/null 2>&1
kubectl --context "${context}" -n "${namespace}" create secret tls "${tls_secret_name}" \
    --cert="${tls_cert_file}" --key="${tls_key_file}"

# Deploy a pod that mounts both fixture secrets and uses the fixture service account.
kubectl --context "${context}" -n "${namespace}" apply -f - <<POD
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  serviceAccountName: ${service_account_name}
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: ${secret_name}
      mountPath: /var/run/peirates-nodefs-fixture
      readOnly: true
    - name: ${tls_secret_name}
      mountPath: /var/run/peirates-nodefs-tls-fixture
      readOnly: true
  volumes:
  - name: ${secret_name}
    secret:
      secretName: ${secret_name}
  - name: ${tls_secret_name}
    secret:
      secretName: ${tls_secret_name}
POD

# Wait for the fixture pod to be ready before inspecting its node filesystem data.
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=120s

# Resolve the pod's kubelet secret paths and confirm the fixtures were mounted.
pod_uid="$(kubectl --context "${context}" -n "${namespace}" get pod "${pod_name}" \
    -o jsonpath='{.metadata.uid}')"
secret_dir="/var/lib/kubelet/pods/${pod_uid}/volumes/kubernetes.io~secret/${secret_name}"
tls_secret_dir="/var/lib/kubelet/pods/${pod_uid}/volumes/kubernetes.io~secret/${tls_secret_name}"
if ! docker exec "${node_name}" test -f "${secret_dir}/fixture"; then
    echo "fixture Secret was not mounted on the Kind node" >&2
    exit 1
fi
if ! docker exec "${node_name}" grep -Fxq "${fixture_value}" "${secret_dir}/fixture"; then
    echo "node-side fixture Secret did not contain the expected disposable value" >&2
    exit 1
fi
if ! docker exec "${node_name}" test -f "${tls_secret_dir}/tls.crt"; then
    echo "fixture TLS certificate was not mounted on the Kind node" >&2
    exit 1
fi

# Build Peirates for the Kind node and install it inside the node container.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
docker cp "${peirates_binary}" "${node_name}:/peirates"
docker exec "${node_name}" chmod 0755 /peirates

# Run the node filesystem secret-stealing module and capture its combined output.
output="$(timeout 90s docker exec "${node_name}" /peirates -c -m nodefs-steal-secrets 2>&1)"

# Confirm Peirates dispatched and entered the requested module.
module_marker="Attempting menu option nodefs-steal-secrets"
module_warning="Attempting to steal secrets from the node filesystem"
if [[ "${output}" != *"${module_marker}"* ]]; then
    echo "Peirates did not dispatch the nodefs-steal-secrets module" >&2
    printf '%s\n' "${output}" >&2
    exit 1
fi
if [[ "${output}" != *"${module_warning}"* ]]; then
    echo "Peirates did not run the nodefs-steal-secrets module" >&2
    printf '%s\n' "${output}" >&2
    exit 1
fi

# Confirm startup discovery identified the fixture service-account token.
service_account_identity="short-lived-sa/${namespace}:${service_account_name}"
service_account_record="Found a short-lived service account token on this node - in pod ${pod_name} service account: ${service_account_identity}"
if [[ "${output}" != *"${service_account_record}"* ]]; then
    echo "nodefs startup discovery did not find the fixture service-account token" >&2
    printf '%s\n' "${output}" >&2
    exit 1
fi

# Check module-specific findings and summary counts after the dispatch marker.
module_output="${output#*${module_marker}}"
for expected in \
    "Secret *** ${secret_name} *** found on pod with etc hosts entry ${pod_name} can be viewed via ls ${secret_dir}" \
    "via a secret on the node's filesystem called ${tls_secret_name}, provided to pod ${pod_name}" \
    "SUMMARY: 1 certificates found in secrets in this node's /var/lib/kubelet/pods/ directory" \
    "SUMMARY: 1 other secrets found in this node's /var/lib/kubelet/pods/ directory"; do
    if [[ "${module_output}" != *"${expected}"* ]]; then
        echo "nodefs-steal-secrets output after module dispatch did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
done

# Report successful completion of all live integration assertions.
echo "nodefs-steal-secrets passed live node integration testing for opaque, TLS, and service-account secrets"
