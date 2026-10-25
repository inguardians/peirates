#!/usr/bin/env bash
# Exercise real AWS signing against mocked IMDS/AWS discovery and a real Kind
# API using a controlled, independently validating authentication webhook.
# No AWS resources or credentials are used. Only this invocation's disposable
# cluster is removed; existing clusters are refused and preserved.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_AWS_NODE_TOKEN_KIND_CLUSTER:-peirates-aws-node-token-integration}"
node_name="${cluster_name}-control-plane"
kubeconfig_file=""
fixture_dir=""
cluster_claim=""
cluster_ownership=none
cleanup() {
    local original_status="$?"
    if [[ -n "${fixture_dir}" ]] && ! rm -rf -- "${fixture_dir}"; then
        original_status=1
    fi
    finish_kind_script_cleanup "${original_status}" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup
umask 077
for required in kind kubectl docker go timeout openssl base64; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
kubeconfig_file="$(mktemp /tmp/peirates-aws-node-kubeconfig.XXXXXX)"
fixture_dir="$(mktemp -d /tmp/peirates-aws-node-fixture.XXXXXX)"
export KUBECONFIG="${kubeconfig_file}"
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "${fixture_dir}/webhook.key" -out "${fixture_dir}/webhook.crt" \
    -subj /CN=peirates-kind-webhook -addext subjectAltName=IP:127.0.0.1 >/dev/null 2>&1
webhook_ca="$(base64 <"${fixture_dir}/webhook.crt" | tr -d '\n')"
cat >"${fixture_dir}/webhook.kubeconfig" <<WEBHOOK
apiVersion: v1
kind: Config
clusters:
- name: fixture
  cluster:
    server: https://127.0.0.1:9443/authenticate
    certificate-authority-data: ${webhook_ca}
users:
- name: fixture
  user: {}
contexts:
- name: fixture
  context: {cluster: fixture, user: fixture}
current-context: fixture
WEBHOOK
cat >"${fixture_dir}/kind.yaml" <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: ${fixture_dir}
    containerPath: /etc/peirates-aws-node-fixture
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
      - name: authentication-token-webhook-config-file
        value: /etc/peirates-aws-node-fixture/webhook.kubeconfig
      - name: authentication-token-webhook-cache-ttl
        value: 0s
      extraVolumes:
      - name: peirates-aws-node-fixture
        hostPath: /etc/peirates-aws-node-fixture
        mountPath: /etc/peirates-aws-node-fixture
        readOnly: true
        pathType: Directory
KIND
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${fixture_dir}/kind.yaml" --wait 120s
build_go_package_for_kind_node "${root_dir}" "${fixture_dir}/webhook" "${node_name}" ./test/fixtures/aws-node-webhook
# The API server uses host networking, so this fixture is bound only to the
# disposable node's loopback interface and is unreachable outside that node.
docker exec -d "${node_name}" /etc/peirates-aws-node-fixture/webhook \
    -cert /etc/peirates-aws-node-fixture/webhook.crt \
    -key /etc/peirates-aws-node-fixture/webhook.key \
    -cluster fixture-cluster -node "${node_name}"
for attempt in $(seq 1 30); do
    if docker exec "${node_name}" bash -c 'echo > /dev/tcp/127.0.0.1/9443' 2>/dev/null; then break; fi
    if [[ "${attempt}" == 30 ]]; then echo 'controlled webhook did not start' >&2; exit 1; fi
    sleep 1
done
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"${fixture_dir}/api-ca.crt"
kubectl config view --raw --minify -o jsonpath='{.users[0].user.client-certificate-data}' | base64 -d >"${fixture_dir}/admin.crt"
kubectl config view --raw --minify -o jsonpath='{.users[0].user.client-key-data}' | base64 -d >"${fixture_dir}/admin.key"
api_server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
# The tagged test invokes the production command handler with a test-only
# provider seam. It then independently calls the live API and checks state.
(cd "${root_dir}" && PEIRATES_AWS_KIND_API_SERVER="${api_server}" \
    PEIRATES_AWS_KIND_CA="${fixture_dir}/api-ca.crt" \
    PEIRATES_AWS_KIND_CERT="${fixture_dir}/admin.crt" \
    PEIRATES_AWS_KIND_KEY="${fixture_dir}/admin.key" \
    PEIRATES_AWS_KIND_NODE="${node_name}" \
    timeout 180s go test -count=1 -tags aws_node_kind ./internal/app -run '^TestAWSNodeTokenKind$' -v)
# Ordinary admin access remains usable after the isolated credential tests.
kubectl get node "${node_name}" -o name >/dev/null
echo 'AWS node token controlled Kind authentication and session assertions passed (EKS acceptance remains separate)'
