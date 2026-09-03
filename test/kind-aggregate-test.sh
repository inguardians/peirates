#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
test_dir="$(mktemp -d /tmp/peirates-kind-aggregate-test.XXXXXX)"
mock_bin="${test_dir}/bin"
mkdir -p "${mock_bin}"

cleanup() {
    rm -rf "${test_dir}"
}
trap cleanup EXIT

cat >"${mock_bin}/kind" <<'MOCK_KIND'
#!/usr/bin/env bash
set -euo pipefail

[[ "${1:-} ${2:-}" == "get clusters" ]]
printf 'enumerate\n' >>"${MOCK_LOG}"
case "${MOCK_ENUMERATION:-clean}" in
    clean)
        ;;
    leaked)
        printf '%s\n' "${MOCK_CLUSTER}"
        ;;
    failure)
        echo "mock Kind enumeration failed" >&2
        exit 44
        ;;
esac
MOCK_KIND

cat >"${test_dir}/mock-test" <<'MOCK_TEST'
#!/usr/bin/env bash
set -euo pipefail

printf '%s=%s\n' "${MOCK_CLUSTER_VARIABLE}" "${!MOCK_CLUSTER_VARIABLE}" >>"${MOCK_LOG}"
exit "${MOCK_TEST_STATUS:-0}"
MOCK_TEST
chmod +x "${mock_bin}/kind" "${test_dir}/mock-test"

run_case() {
    local scenario="$1" test_status="$2" expected_status="$3" expected_text="$4"
    local cluster="aggregate-${scenario}"
    local log="${test_dir}/${scenario}.log"
    local output status

    : >"${log}"
    set +e
    output="$(env PATH="${mock_bin}:${PATH}" MOCK_LOG="${log}" \
        MOCK_CLUSTER="${cluster}" MOCK_CLUSTER_VARIABLE=TEST_KIND_CLUSTER \
        MOCK_ENUMERATION="${scenario}" MOCK_TEST_STATUS="${test_status}" \
        TEST_KIND_CLUSTER="${cluster}" "${root_dir}/test/run-kind-tests.sh" \
        "mock-target:TEST_KIND_CLUSTER:aggregate-default:${test_dir}/mock-test" 2>&1)"
    status=$?
    set -e
    if [[ "${status}" != "${expected_status}" || "${output}" != *"${expected_text}"* ]]; then
        echo "aggregate ${scenario}: unexpected status or output" >&2
        printf 'status=%s\n%s\n' "${status}" "${output}" >&2
        exit 1
    fi
    grep -Fxq "TEST_KIND_CLUSTER=${cluster}" "${log}"
    [[ "$(grep -c '^enumerate$' "${log}" || true)" == 1 ]]
}

run_case clean 0 0 "Verified absent after mock-target"
run_case clean 37 37 "mock-target failed with exit status 37"
run_case leaked 0 1 "cluster remains: aggregate-leaked"
run_case failure 0 1 "cleanup is unverified"
run_case failure 37 37 "cleanup is unverified"

fixture_token='eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature'
redacted="$(redact_service_account_token_output \
    "prefix ${fixture_token} suffix ${fixture_token}" "${fixture_token}")"
[[ "${redacted}" == 'prefix [REDACTED SERVICE ACCOUNT TOKEN] suffix [REDACTED SERVICE ACCOUNT TOKEN]' ]]
[[ "${redacted}" != *"${fixture_token}"* ]]

# A failing first case is deterministic fail-fast: the second case is never
# started, even though cleanup verification for the first case still runs.
fail_fast_log="${test_dir}/fail-fast.log"
: >"${fail_fast_log}"
set +e
env PATH="${mock_bin}:${PATH}" MOCK_LOG="${fail_fast_log}" \
    MOCK_CLUSTER=aggregate-fail-fast MOCK_CLUSTER_VARIABLE=TEST_KIND_CLUSTER \
    MOCK_ENUMERATION=clean MOCK_TEST_STATUS=37 \
    "${root_dir}/test/run-kind-tests.sh" \
    "first:TEST_KIND_CLUSTER:aggregate-first:${test_dir}/mock-test" \
    "second:TEST_KIND_CLUSTER:aggregate-second:${test_dir}/mock-test" \
    >/dev/null 2>&1
fail_fast_status=$?
set -e
[[ "${fail_fast_status}" == 37 ]]
[[ "$(grep -c '^TEST_KIND_CLUSTER=' "${fail_fast_log}" || true)" == 1 ]]
[[ "$(grep -c '^enumerate$' "${fail_fast_log}" || true)" == 1 ]]

# The Make inventory, executable integration scripts, and CI matrix must stay
# in exact 15-entry parity, and the intentionally retained manual harness must
# never appear in either automated inventory.
mapfile -t make_targets < <(make -s -C "${root_dir}" --no-print-directory kind-test-inventory)
mapfile -t workflow_targets < <(awk '/^[[:space:]]+- target:/ { print $3 }' \
    "${root_dir}/.github/workflows/kind.yaml")
mapfile -t integration_scripts < <(find "${root_dir}/test" -maxdepth 1 \
    -type f -name '*kind-integration.sh' -printf '%f\n' | LC_ALL=C sort)

[[ "${#make_targets[@]}" == 15 ]]
[[ "${#workflow_targets[@]}" == 15 ]]
[[ "${#integration_scripts[@]}" == 15 ]]
[[ "${make_targets[*]}" == "${workflow_targets[*]}" ]]
[[ " ${make_targets[*]} " != *" kubelet-kind-manual "* ]]

# CI stays pull-request-only/read-only, pins actions by immutable SHA, redacts
# JWT-shaped tokens before logging, and reserves cleanup headroom beyond the
# per-test command timeout. Its Kubernetes minor and node digest match go.mod
# and the shared Kind helper.
workflow="${root_dir}/.github/workflows/kind.yaml"
helper="${root_dir}/test/kind-build-helpers.sh"
[[ "$(grep -Ec 'uses: [^@]+@[0-9a-f]{40}( |$)' "${workflow}")" == 3 ]]
! grep -Eq 'uses: [^@]+@v[0-9]' "${workflow}"
grep -Fq 'permissions:' "${workflow}"
grep -Fq 'contents: read' "${workflow}"
grep -Fq 'timeout-minutes: 35' "${workflow}"
grep -Fq 'timeout --foreground --kill-after=2m 20m' "${workflow}"
grep -Fq '[REDACTED SERVICE ACCOUNT TOKEN]' "${workflow}"
grep -Fq 'if: always()' "${workflow}"
! grep -Fq 'KUBECONFIG:' "${workflow}"
grep -Fq 'KUBECTL_VERSION: v1.36.1' "${workflow}"
grep -Fq 'k8s.io/kubectl v0.36.1' "${root_dir}/go.mod"
node_image="kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
grep -Fq "PEIRATES_KIND_NODE_IMAGE: ${node_image}" "${workflow}"
grep -Fq "PEIRATES_KIND_DEFAULT_NODE_IMAGE=\"${node_image}\"" "${helper}"

echo "Kind aggregate cleanup and 15/15/15 inventory regression tests passed"
