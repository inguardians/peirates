#!/usr/bin/env bash
# This integration test creates an isolated Kind cluster and verifies that Peirates
# can use a scoped Kubernetes service-account token to list namespaces.
#
# The script tests:
# - Required local tooling is available before the test starts.
# - A disposable Kind cluster can be created with the expected test RBAC resources.
# - Peirates can authenticate to the cluster and list namespaces through its integration test.
# - Temporary cluster and kubeconfig resources are cleaned up when the script exits.

# Exit on command failures, unset variables, and failed pipeline stages.
set -euo pipefail

# Resolve repository paths and configure the disposable cluster and kubeconfig.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-peirates-integration}"
NAMESPACE="peirates-integration"
KUBECONFIG_FILE="$(mktemp)"
export KUBECONFIG="${KUBECONFIG_FILE}"

# Verify every external command required by the live integration test.
for command in kind kubectl docker go; do
  command -v "${command}" >/dev/null || {
    echo "kind integration tests require ${command}" >&2
    exit 1
  }
done

# Remove the disposable cluster and kubeconfig on every exit path.
cleanup() {
  kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  rm -f "${KUBECONFIG_FILE}"
}
trap cleanup EXIT

# Recreate the isolated Kind cluster from a known state.
kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
kind create cluster --name "${CLUSTER_NAME}" --wait 90s

# Provision the namespace, service account, and view-only RBAC binding.
kubectl create namespace "${NAMESPACE}"
kubectl -n "${NAMESPACE}" create serviceaccount peirates-test
kubectl create clusterrolebinding peirates-test-view \
  --clusterrole=view \
  --serviceaccount="${NAMESPACE}:peirates-test"

# Obtain live cluster credentials for the tagged Go integration test.
API_SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
TOKEN="$(kubectl -n "${NAMESPACE}" create token peirates-test)"

# Run the namespace-listing integration test against the disposable API server.
(
  cd "${ROOT_DIR}"
  PEIRATES_KIND_API_SERVER="${API_SERVER}" \
    PEIRATES_KIND_TOKEN="${TOKEN}" \
    go test -v -timeout 30s -tags=integration -run '^TestKindListsNamespaces$' ./...
)
