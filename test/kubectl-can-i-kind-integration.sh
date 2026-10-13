#!/usr/bin/env bash
# Verify kubectl-can-i against real stored service-account and certificate
# credentials without executing the requested create-pods action.
# Explicit namespace overrides, denied identities, certificate revocation,
# unchanged current authentication, and pod inventories are checked independently.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_KUBECTL_CAN_I_KIND_CLUSTER:-peirates-kubectl-can-i-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-can-i-source"
target_namespace="peirates-can-i-target"
allowed_account="peirates-can-i-allowed"
denied_account="peirates-can-i-denied"
allowed_secret="peirates-can-i-allowed-token-live"
denied_secret="peirates-can-i-denied-token-live"
certificate_identity="peirates-can-i-certificate"
runner_pod="peirates-can-i-runner"
role_name="peirates-can-i-creator"
kubeconfig_file=""
fixture_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

cleanup() {
    local original_status="$?"
    local -a cleanup_files=("${kubeconfig_file}" "${peirates_binary}")
    if [[ -n "${fixture_file}" ]]; then
        cleanup_files+=("${fixture_file}" "${fixture_file}.key" "${fixture_file}.csr"
            "${fixture_file}.crt" "${fixture_file}.ca" "${fixture_file}.kubeconfig")
    fi
    finish_kind_script_cleanup "${original_status}" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" "${cleanup_files[@]}"
}
install_kind_script_traps cleanup
umask 077
kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
export KUBECONFIG="${kubeconfig_file}"
fixture_file="$(mktemp /tmp/peirates-can-i-fixture.XXXXXX)"
peirates_binary="$(mktemp /tmp/peirates-can-i-binary.XXXXXX)"
for required in kind kubectl docker go timeout openssl base64 grep sed; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --wait 120s

kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" create namespace "${target_namespace}"
for service_account in "${allowed_account}" "${denied_account}"; do
    kubectl --context "${context}" -n "${namespace}" create serviceaccount "${service_account}"
done
kubectl --context "${context}" -n "${target_namespace}" create role "${role_name}" \
    --verb=create --resource=pods
kubectl --context "${context}" -n "${target_namespace}" create rolebinding "${role_name}-token" \
    --role="${role_name}" --serviceaccount="${namespace}:${allowed_account}"
kubectl --context "${context}" -n "${target_namespace}" create rolebinding "${role_name}-cert" \
    --role="${role_name}" --user="${certificate_identity}"

# Issue a real client certificate for an ordinary, namespace-limited user.
# A kubelet's own identity can create mirror pods and is unsuitable for this check.
openssl req -new -newkey rsa:2048 -nodes -keyout "${fixture_file}.key" \
    -out "${fixture_file}.csr" -subj "/CN=${certificate_identity}" >/dev/null 2>&1
csr_data="$(base64 <"${fixture_file}.csr" | tr -d '\n')"
kubectl --context "${context}" apply -f - <<CSR
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${certificate_identity}
spec:
  request: ${csr_data}
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 3600
  usages: [client auth]
CSR
kubectl --context "${context}" certificate approve "${certificate_identity}"
kubectl --context "${context}" wait --for=jsonpath='{.status.certificate}' \
    "csr/${certificate_identity}" --timeout=60s
kubectl --context "${context}" get csr "${certificate_identity}" \
    -o jsonpath='{.status.certificate}' | base64 -d >"${fixture_file}.crt"
kubectl --context "${context}" config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"${fixture_file}.ca"
api_server="$(kubectl --context "${context}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

# The runner exposes only this fixture kubeconfig at a standard discovery path.
# Embedded data makes the certificate portable between the host and runner pod.
kubectl --kubeconfig="${fixture_file}.kubeconfig" config set-cluster fixture \
    --server=https://kubernetes.default.svc --certificate-authority="${fixture_file}.ca" --embed-certs=true >/dev/null
kubectl --kubeconfig="${fixture_file}.kubeconfig" config set-credentials "${certificate_identity}" \
    --client-certificate="${fixture_file}.crt" --client-key="${fixture_file}.key" --embed-certs=true >/dev/null
kubectl --context "${context}" -n "${namespace}" create secret generic peirates-can-i-certificate \
    --from-file="kubeconfig=${fixture_file}.kubeconfig"

for token_fixture in "${allowed_secret}:${allowed_account}" "${denied_secret}:${denied_account}"; do
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
cat >"${fixture_file}" <<RUNNER
apiVersion: v1
kind: Pod
metadata:
  name: ${runner_pod}
  namespace: ${namespace}
spec:
  serviceAccountName: ${denied_account}
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: certificate
      mountPath: /var/lib/kubelet/kubeconfig
      subPath: kubeconfig
      readOnly: true
    - name: ${allowed_secret}
      mountPath: /var/lib/kubelet/pods/010-allowed/volumes/kubernetes.io~secret/${allowed_secret}
      readOnly: true
    - name: ${denied_secret}
      mountPath: /var/lib/kubelet/pods/020-denied/volumes/kubernetes.io~secret/${denied_secret}
      readOnly: true
  volumes:
  - name: certificate
    secret:
      secretName: peirates-can-i-certificate
  - name: ${allowed_secret}
    secret:
      secretName: ${allowed_secret}
  - name: ${denied_secret}
    secret:
      secretName: ${denied_secret}
RUNNER
kubectl --context "${context}" apply -f "${fixture_file}"
kubectl --context "${context}" -n "${namespace}" wait --for=condition=Ready \
    "pod/${runner_pod}" --timeout=120s

# Assert authorizations independently of Peirates; authenticate the actual cert.
assert_can_i() {
    local expected="$1" identity="$2" scope="$3" result status=0
    local -a auth_args
    if [[ "${identity}" == certificate ]]; then
        auth_args=(--kubeconfig=/dev/null --server="${api_server}"
            --certificate-authority="${fixture_file}.ca"
            --client-certificate="${fixture_file}.crt" --client-key="${fixture_file}.key")
    else
        auth_args=(--context "${context}" --as="system:serviceaccount:${namespace}:${identity}")
    fi
    result="$(kubectl "${auth_args[@]}" auth can-i create pods --namespace="${scope}")" || status=$?
    if [[ "${result}" != "${expected}" || "${status}" -gt 1 ]]; then
        echo "independent can-i assertion failed for ${identity} in ${scope}: expected ${expected}" >&2
        exit 1
    fi
}
for identity in "${allowed_account}" certificate; do
    assert_can_i yes "${identity}" "${target_namespace}"
    assert_can_i no "${identity}" "${namespace}"
    assert_can_i no "${identity}" default
done
assert_can_i no "${denied_account}" "${target_namespace}"

build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${runner_pod}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- chmod 0755 /tmp/peirates
run_module() {
    timeout 90s kubectl --context "${context}" -n "${namespace}" exec "${runner_pod}" -- \
        /tmp/peirates -c -m "$1"
}
assert_contains() {
    if [[ "$1" != *"$2"* ]]; then
        echo "$3: missing expected output: $2" >&2
        exit 1
    fi
}
assert_absent() {
    if [[ "$1" == *"$2"* ]]; then
        echo "$3: unexpected output marker or credential disclosure" >&2
        exit 1
    fi
}
assert_permitted() {
    local output="$1" scenario="$2" expected_count="$3"
    local count=0 remainder="$1" marker='[+] Permitted:'
    assert_contains "${output}" '0 failed' "${scenario}"
    assert_absent "${output}" '[-] Check failed:' "${scenario}"
    # The interactive prompt can precede the first result on the same line.
    # Count exact result markers regardless of their position on a line.
    while [[ "${remainder}" == *"${marker}"* ]]; do
        remainder="${remainder#*"${marker}"}"
        count=$((count + 1))
    done
    if [[ "${count}" != "${expected_count}" ]]; then
        echo "${scenario}: expected ${expected_count} permitted identities, got ${count}" >&2
        exit 1
    fi
    assert_absent "${output}" "[+] Permitted: service account \"${namespace}/${denied_secret}\"" "${scenario}"
    assert_absent "${output}" "[+] Permitted: service account \"${namespace}:${denied_account}\"" "${scenario}"
    assert_absent "${output}" '-----BEGIN PRIVATE KEY-----' "${scenario}"
    for token_secret in "${allowed_secret}" "${denied_secret}"; do
        token_value="$(kubectl --context "${context}" -n "${namespace}" get secret "${token_secret}" \
            -o jsonpath='{.data.token}' | base64 -d)"
        assert_absent "${output}" "${token_value}" "${scenario}"
    done
}
pod_inventory() {
    kubectl --context "${context}" get pods -A \
        -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}/{.metadata.uid}{"\n"}{end}'
}
initial_pods="$(pod_inventory)"
allowed_marker="[+] Permitted: service account \"${namespace}/${allowed_secret}\""
cert_marker="[+] Permitted: certificate \"${certificate_identity}\""

for arguments in "-n ${target_namespace} create pods" "create pods --namespace=${target_namespace}"; do
    output="$(run_module "kubectl-can-i ${arguments}" 2>&1)"
    assert_permitted "${output}" "${arguments}" 2
    assert_contains "${output}" "${allowed_marker}" "${arguments}"
    assert_contains "${output}" "${cert_marker}" "${arguments}"
done
for arguments in "create pods" "-n default create pods" "--all-namespaces create pods"; do
    output="$(run_module "kubectl-can-i ${arguments}" 2>&1)"
    assert_permitted "${output}" "${arguments}" 0
done

# Keep the permission check and follow-up in one process. Existing menu readers
# require separately delivered lines for the startup pause and command pauses.
interactive_output="$({
    printf 'continue\n'; sleep 1
    printf 'kubectl-can-i -n %s create pods\n' "${target_namespace}"; sleep 3
    printf 'continue\n'; sleep 1
    printf 'kubectl auth whoami -o jsonpath={.status.userInfo.username}\n'; sleep 3
    printf 'continue\n'; sleep 1
    printf 'exit\n'
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${runner_pod}" -- \
    /tmp/peirates -c 2>&1)"
assert_permitted "${interactive_output}" 'interactive session' 2
assert_contains "${interactive_output}" "${allowed_marker}" 'interactive session'
assert_contains "${interactive_output}" "${cert_marker}" 'interactive session'
assert_contains "${interactive_output}" "system:serviceaccount:${namespace}:${denied_account}" 'preserved authentication'
# Restrict the namespace check to banners printed after the permission results.
post_check="${interactive_output#*"${cert_marker}"}"
assert_contains "${post_check}" "[+] Current namespace                 : ${namespace}" 'preserved namespace'
assert_absent "${post_check}" "[+] Current namespace                 : ${target_namespace}" 'preserved namespace'

# Remove only the cert grant, proving a valid denied certificate is omitted.
kubectl --context "${context}" -n "${target_namespace}" delete rolebinding "${role_name}-cert"
assert_can_i no certificate "${target_namespace}"
output="$(run_module "kubectl-can-i -n ${target_namespace} create pods" 2>&1)"
assert_permitted "${output}" 'denied certificate' 1
assert_contains "${output}" "${allowed_marker}" 'denied certificate'
assert_absent "${output}" "${cert_marker}" 'denied certificate'
if [[ "$(pod_inventory)" != "${initial_pods}" ]]; then
    echo 'pod inventory changed during read-only permission checks' >&2
    exit 1
fi
echo 'kubectl-can-i passed live identity, namespace, denial, current-auth, and read-only assertions'
