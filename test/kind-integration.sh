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

# Resolve repository paths and configure ownership-tracked disposable state.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-peirates-integration}"
NAMESPACE="peirates-integration"
KUBECONFIG_FILE=""
CLUSTER_OWNERSHIP=none
CLUSTER_CLAIM=""

# Delete only a cluster for which this invocation has positive provenance.
cleanup() {
  finish_kind_script_cleanup "$?" "${CLUSTER_NAME}" "${KUBECONFIG_FILE}" \
    "${CLUSTER_OWNERSHIP}" "${CLUSTER_CLAIM}" "${KUBECONFIG_FILE}"
}
install_kind_script_traps cleanup

KUBECONFIG_FILE="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${KUBECONFIG_FILE}"
export KUBECONFIG="${KUBECONFIG_FILE}"

# Verify every external command required by the live integration test.
for command in kind kubectl docker go; do
  command -v "${command}" >/dev/null || {
    echo "kind integration tests require ${command}" >&2
    exit 1
  }
done

# Serialize participating runs, refuse existing names, and record durable
# ownership provenance before cleanup is allowed to delete anything.
acquire_kind_cluster_claim "${CLUSTER_NAME}" CLUSTER_CLAIM
require_absent_kind_cluster "${CLUSTER_NAME}"
create_kind_cluster_with_provenance "${CLUSTER_NAME}" "${KUBECONFIG_FILE}" \
  CLUSTER_OWNERSHIP --wait 90s

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
