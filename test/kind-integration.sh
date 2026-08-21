#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-peirates-integration}"
NAMESPACE="peirates-integration"
KUBECONFIG_FILE="$(mktemp)"
export KUBECONFIG="${KUBECONFIG_FILE}"

for command in kind kubectl docker go; do
  command -v "${command}" >/dev/null || {
    echo "kind integration tests require ${command}" >&2
    exit 1
  }
done

cleanup() {
  kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  rm -f "${KUBECONFIG_FILE}"
}
trap cleanup EXIT

kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
kind create cluster --name "${CLUSTER_NAME}" --wait 90s

kubectl create namespace "${NAMESPACE}"
kubectl -n "${NAMESPACE}" create serviceaccount peirates-test
kubectl create clusterrolebinding peirates-test-view \
  --clusterrole=view \
  --serviceaccount="${NAMESPACE}:peirates-test"

API_SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
TOKEN="$(kubectl -n "${NAMESPACE}" create token peirates-test)"

(
  cd "${ROOT_DIR}"
  PEIRATES_KIND_API_SERVER="${API_SERVER}" \
    PEIRATES_KIND_TOKEN="${TOKEN}" \
    go test -v -timeout 30s -tags=integration -run '^TestKindListsNamespaces$' ./...
)
