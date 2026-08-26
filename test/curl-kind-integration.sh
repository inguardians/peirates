#!/usr/bin/env bash
# This live integration test verifies that Peirates main-menu item 91 can issue
# HTTP requests from inside a disposable Kind cluster through both supported flows.
#
# The script tests:
# - Creation of an isolated Kind cluster with server and runner pods.
# - Deployment and readiness of the HTTP request fixture.
# - Interactive wizard input for a POST request with headers and body parameters.
# - Direct module dispatch for the equivalent non-wizard POST request.
# - Expected Peirates prompts, request summaries, and fixture response markers.

# Exit on errors, unset variables, and failed pipeline commands.
set -euo pipefail

# Resolve repository paths, create temporary files, and define test resources.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_CURL_KIND_CLUSTER:-peirates-curl-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-curl-test"
server_pod="peirates-curl-server"
server_service="peirates-curl-server"
runner_pod="peirates-curl-runner"
wizard_marker="peirates-item-91-wizard-response"
direct_marker="peirates-item-91-direct-response"
kubeconfig_file=""
config_file=""
peirates_binary=""
server_binary=""
cluster_created=false

# Tear down the owned cluster and generated files on exit.
cleanup() {
    trap '' INT TERM
    if [[ "${cluster_created}" == true ]]; then
        kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${config_file}" "${peirates_binary}" "${server_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-curl-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-curl-binary.XXXXXX)"
server_binary="$(mktemp /tmp/peirates-curl-server-binary.XXXXXX)"

# Check prerequisites and guard against modifying an existing cluster.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"; then
    echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
    exit 1
fi

# Create the disposable cluster, namespace, HTTP fixture, and runner pod.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
cluster_created=true
kind create cluster --name "${cluster_name}" --config "${config_file}" \
    --image "$(kind_node_image)" --wait 120s
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" apply -f - <<SERVER
apiVersion: v1
kind: Pod
metadata:
  name: ${server_pod}
  labels:
    app: ${server_pod}
spec:
  containers:
  - name: server
    image: busybox:1.36.1
    command: ["sh", "-c"]
    args:
    - |
      while [ ! -x /tmp/http-request-server ]; do
        sleep 1
      done
      exec /tmp/http-request-server
---
apiVersion: v1
kind: Service
metadata:
  name: ${server_service}
spec:
  selector:
    app: ${server_pod}
  ports:
  - name: http
    port: 8080
    targetPort: 8080
SERVER
kubectl --context "${context}" -n "${namespace}" run "${runner_pod}" \
    --image=busybox:1.36.1 --restart=Never --command -- sh -c 'sleep 3600'
# Wait for both fixture pods before installing test binaries.
for pod in "${server_pod}" "${runner_pod}"; do
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=condition=Ready "pod/${pod}" --timeout=120s
done

# Cross-compile and install the HTTP fixture and Peirates binaries.
build_go_package_for_kind_node "${root_dir}" "${server_binary}" "${node_name}" \
    ./test/fixtures/http-request-server
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp \
    "${server_binary}" "${server_pod}:/tmp/http-request-server"
kubectl --context "${context}" -n "${namespace}" exec "${server_pod}" -- chmod 0755 /tmp/http-request-server
kubectl --context "${context}" -n "${namespace}" cp \
    "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- chmod 0755 /tmp/peirates

# Poll the in-cluster HTTP fixture until it accepts requests.
server_ready=false
for _ in {1..50}; do
    if health="$(kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- \
        wget -qO- "http://${server_service}:8080/healthz" 2>/dev/null)" && [[ "${health}" == "ok" ]]; then
        server_ready=true
        break
    fi
    sleep 0.2
done
if [[ "${server_ready}" != true ]]; then
    echo "HTTP request fixture did not become ready" >&2
    kubectl --context "${context}" -n "${namespace}" logs "${server_pod}" >&2 || true
    exit 1
fi

# Print captured output only when a request flow fails.
fail_output() {
    local message="$1" output="$2"
    echo "${message}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
}
# Require an expected prompt, summary, or response marker in output.
assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        fail_output "item 91 ${scenario} output did not contain: ${expected}" "${output}"
    fi
}

# Drive the interactive curl wizard and validate its POST request details.
wizard_url="http://${server_service}:8080/wizard"
if ! wizard_output="$({ printf '91\n'; sleep 1; printf '%s\n' "${wizard_url}"; sleep 1; \
    printf 'POST\n'; sleep 1; \
    printf 'X-Peirates-Mode\n'; sleep 1; printf 'wizard\n'; sleep 1; \
    printf 'X-Peirates-Trace\n'; sleep 1; printf 'wizard-trace\n'; sleep 1; \
    printf '\n'; sleep 1; \
    printf 'alpha\n'; sleep 1; printf 'wizard-one\n'; sleep 1; \
    printf 'beta\n'; sleep 1; printf 'wizard-two\n'; sleep 1; \
    printf '\n'; sleep 1; printf 'body\n'; sleep 1; \
    printf 'continue\n'; sleep 1; printf 'exit\n'; } | \
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${runner_pod}" -- \
        /tmp/peirates -c 2>&1)"; then
    fail_output "item 91 wizard execution failed" "${wizard_output}"
fi
assert_contains "${wizard_output}" "[+] Enter a URL" "wizard"
assert_contains "${wizard_output}" "[+] Enter method" "wizard"
assert_contains "${wizard_output}" "[+] Specify custom header lines" "wizard headers"
assert_contains "${wizard_output}" "[+] Now enter parameters" "wizard body variables"
assert_contains "${wizard_output}" "[+] Using method POST for URL ${wizard_url}" "wizard"
assert_contains "${wizard_output}" "${wizard_marker}" "wizard response"

# Dispatch curl directly and validate the equivalent POST request.
direct_url="http://${server_service}:8080/direct"
direct_module="curl -X POST -H X-Peirates-Mode:direct -H X-Peirates-Trace:direct-trace"
direct_module+=" -d alpha=direct-one -d beta=direct-two ${direct_url}"
if ! direct_output="$(timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- \
    /tmp/peirates -c -m "${direct_module}" 2>&1)"; then
    fail_output "item 91 non-wizard execution failed" "${direct_output}"
fi
assert_contains "${direct_output}" "Attempting menu option ${direct_module}" "non-wizard dispatch"
assert_contains "${direct_output}" "[+] Using method POST for URL ${direct_url}" "non-wizard"
assert_contains "${direct_output}" "${direct_marker}" "non-wizard response"

# Report completion after both request paths pass.
echo "main-menu item 91 passed live integration testing for wizard and non-wizard requests"
