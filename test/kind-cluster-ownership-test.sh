#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d /tmp/peirates-kind-cluster-ownership-test.XXXXXX)"
mock_bin="${test_dir}/bin"
claim_root="${test_dir}/claims"
mkdir -p "${mock_bin}" "${claim_root}"

cleanup_test() {
    trap - EXIT
    trap '' INT TERM
    if [[ -n "${active_pid:-}" ]]; then
        kill -TERM "${active_pid}" 2>/dev/null || true
        wait "${active_pid}" 2>/dev/null || true
    fi
    rm -rf "${test_dir}"
}
trap cleanup_test EXIT

cat >"${mock_bin}/kind" <<'MOCK_KIND'
#!/usr/bin/env bash
set -euo pipefail

printf 'kind %s\n' "$*" >>"${MOCK_LOG}"
command_name="${1:-} ${2:-}"
case "${command_name}" in
    "get clusters")
        case "${MOCK_SCENARIO}" in
            existing)
                printf '%s\n' "${MOCK_CLUSTER}"
                ;;
            enumeration-failure)
                echo "mock enumeration failure" >&2
                exit 41
                ;;
        esac
        ;;
    "create cluster")
        kubeconfig="${KUBECONFIG:-}"
        while (($#)); do
            if [[ "$1" == --kubeconfig ]]; then
                kubeconfig="$2"
                break
            fi
            shift
        done
        case "${MOCK_SCENARIO}" in
            partial-provenance)
                printf 'kind-%s\n' "${MOCK_CLUSTER}" >"${kubeconfig}"
                exit 42
                ;;
            partial-ambiguous|concurrent-external)
                printf 'external same-name resource %s\n' "${MOCK_CLUSTER}" >>"${MOCK_LOG}"
                exit 42
                ;;
            claim-holder)
                : >"${MOCK_CREATE_READY}"
                while [[ ! -e "${MOCK_CREATE_RELEASE}" ]]; do sleep 0.05; done
                exit 42
                ;;
            later-failure|delete-failure|normal-signal|signal-cleanup)
                printf 'kind-%s\n' "${MOCK_CLUSTER}" >"${kubeconfig}"
                ;;
        esac
        ;;
    "delete cluster")
        case "${MOCK_SCENARIO}" in
            delete-failure)
                echo "mock deletion failure" >&2
                exit 55
                ;;
            signal-cleanup)
                : >"${MOCK_DELETE_READY}"
                while [[ ! -e "${MOCK_DELETE_RELEASE}" ]]; do sleep 0.05; done
                : >"${MOCK_DELETE_DONE}"
                ;;
        esac
        ;;
esac
MOCK_KIND

cat >"${mock_bin}/kubectl" <<'MOCK_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail

printf 'kubectl %s\n' "$*" >>"${MOCK_LOG}"
kubeconfig="${KUBECONFIG:-}"
arguments=" $* "
while (($#)); do
    if [[ "$1" == --kubeconfig ]]; then
        kubeconfig="$2"
        break
    fi
    shift
done
if [[ "${arguments}" == *" config get-contexts -o name "* ]]; then
    grep '^kind-' "${kubeconfig}"
    exit $?
fi
case "${MOCK_SCENARIO}" in
    later-failure|delete-failure)
        exit 43
        ;;
    normal-signal|signal-cleanup)
        : >"${MOCK_SETUP_READY}"
        while :; do sleep 1; done
        ;;
esac
MOCK_KUBECTL

chmod +x "${mock_bin}/kind" "${mock_bin}/kubectl"

count_log() {
    local pattern="$1"
    local log="$2"
    grep -c "${pattern}" "${log}" || true
}

run_script_case() {
    local script="$1"
    local cluster_variable="$2"
    local short_name="$3"
    local scenario="$4"
    local expected_status="$5"
    local expected_create="$6"
    local expected_delete="$7"
    local cluster="ownership-${short_name}-${scenario}"
    local log="${test_dir}/${short_name}-${scenario}.log"
    local output status

    : >"${log}"
    set +e
    output="$(env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_SIGNAL_WORKER=true \
        PEIRATES_KIND_CLAIM_ROOT="${claim_root}" MOCK_SCENARIO="${scenario}" \
        MOCK_CLUSTER="${cluster}" MOCK_LOG="${log}" \
        "${cluster_variable}=${cluster}" bash "${root_dir}/${script}" 2>&1)"
    status=$?
    set -e
    if [[ "${status}" != "${expected_status}" ]]; then
        echo "${script} ${scenario}: status ${status}, expected ${expected_status}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
    if [[ "$(count_log '^kind create cluster ' "${log}")" != "${expected_create}" ||
        "$(count_log '^kind delete cluster ' "${log}")" != "${expected_delete}" ]]; then
        echo "${script} ${scenario}: unexpected create/delete count" >&2
        sed 's/^/  /' "${log}" >&2
        exit 1
    fi
    if [[ "${expected_delete}" == 1 ]] &&
        ! grep -Fxq "kind delete cluster --name ${cluster}" "${log}"; then
        echo "${script} ${scenario}: cleanup did not use the exact configured name" >&2
        exit 1
    fi
    if [[ -e "${claim_root}/${cluster}" ]]; then
        echo "${script} ${scenario}: cluster claim was not released" >&2
        exit 1
    fi
    case "${scenario}" in
        existing)
            [[ "${output}" == *"refusing to modify existing Kind cluster ${cluster}"* ]]
            ;;
        enumeration-failure)
            [[ "${output}" == *"unable to enumerate Kind clusters"* ]]
            ;;
        partial-provenance)
            [[ "${output}" == *"private ownership provenance"* ]]
            ;;
        partial-ambiguous|concurrent-external)
            [[ "${output}" == *"without ownership provenance"* ]]
            ;;
        delete-failure)
            [[ "${output}" == *"failed to delete owned Kind cluster"* ]]
            [[ "${output}" == *"mock deletion failure"* ]]
            ;;
    esac
}

scripts=(
    "test/kind-integration.sh:KIND_CLUSTER_NAME:basic"
    "test/exec-via-api-kind-integration.sh:PEIRATES_EXEC_API_KIND_CLUSTER:exec"
    "test/kubectl-try-all-kind-integration.sh:PEIRATES_KUBECTL_TRY_ALL_KIND_CLUSTER:try-all"
    "test/hostpid-breakout-kind-integration.sh:PEIRATES_HOSTPID_BREAKOUT_KIND_CLUSTER:hostpid"
)
for item in "${scripts[@]}"; do
    IFS=: read -r script cluster_variable short_name <<<"${item}"
    run_script_case "${script}" "${cluster_variable}" "${short_name}" existing 1 0 0
    run_script_case "${script}" "${cluster_variable}" "${short_name}" enumeration-failure 1 0 0
    run_script_case "${script}" "${cluster_variable}" "${short_name}" concurrent-external 42 1 0
    run_script_case "${script}" "${cluster_variable}" "${short_name}" partial-ambiguous 42 1 0
    run_script_case "${script}" "${cluster_variable}" "${short_name}" partial-provenance 42 1 1
    run_script_case "${script}" "${cluster_variable}" "${short_name}" later-failure 43 1 1
    run_script_case "${script}" "${cluster_variable}" "${short_name}" delete-failure 43 1 1
done

# A held claim prevents a second repository invocation from reaching either
# enumeration or creation for the same configured name.
holder_cluster=ownership-concurrent-claim
holder_log="${test_dir}/claim-holder.log"
contender_log="${test_dir}/claim-contender.log"
create_ready="${test_dir}/create-ready"
create_release="${test_dir}/create-release"
: >"${holder_log}"
: >"${contender_log}"
env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_SIGNAL_WORKER=true \
    PEIRATES_KIND_CLAIM_ROOT="${claim_root}" MOCK_SCENARIO=claim-holder \
    MOCK_CLUSTER="${holder_cluster}" MOCK_LOG="${holder_log}" \
    MOCK_CREATE_READY="${create_ready}" MOCK_CREATE_RELEASE="${create_release}" \
    PEIRATES_EXEC_API_KIND_CLUSTER="${holder_cluster}" \
    bash "${root_dir}/test/exec-via-api-kind-integration.sh" >"${test_dir}/holder.out" 2>&1 &
active_pid=$!
for _ in {1..200}; do [[ -e "${create_ready}" ]] && break; sleep 0.01; done
[[ -e "${create_ready}" ]]
set +e
contender_output="$(env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_SIGNAL_WORKER=true \
    PEIRATES_KIND_CLAIM_ROOT="${claim_root}" MOCK_SCENARIO=claim-holder \
    MOCK_CLUSTER="${holder_cluster}" MOCK_LOG="${contender_log}" \
    PEIRATES_EXEC_API_KIND_CLUSTER="${holder_cluster}" \
    bash "${root_dir}/test/exec-via-api-kind-integration.sh" 2>&1)"
contender_status=$?
set -e
[[ "${contender_status}" == 1 ]]
[[ "${contender_output}" == *"refusing Kind test for claimed cluster"* ]]
[[ ! -s "${contender_log}" ]]
: >"${create_release}"
set +e
wait "${active_pid}"
holder_status=$?
set -e
active_pid=""
[[ "${holder_status}" == 42 ]]

# Claims left by an unclean SIGKILL or host failure are never broken
# automatically. They fail closed until an operator verifies and removes them.
stale_cluster=ownership-stale-claim
stale_log="${test_dir}/stale-claim.log"
mkdir "${claim_root}/${stale_cluster}"
: >"${stale_log}"
set +e
stale_output="$(env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_SIGNAL_WORKER=true \
    PEIRATES_KIND_CLAIM_ROOT="${claim_root}" MOCK_SCENARIO=partial-provenance \
    MOCK_CLUSTER="${stale_cluster}" MOCK_LOG="${stale_log}" \
    PEIRATES_EXEC_API_KIND_CLUSTER="${stale_cluster}" \
    bash "${root_dir}/test/exec-via-api-kind-integration.sh" 2>&1)"
stale_status=$?
set -e
[[ "${stale_status}" == 1 ]]
[[ "${stale_output}" == *"stale claim"* ]]
[[ ! -s "${stale_log}" ]]
rmdir "${claim_root}/${stale_cluster}"

# A final-component symlink cannot redirect claims into an attacker-selected
# directory. The helper also checks effective ownership and enforces mode 0700.
unsafe_claim_target="${test_dir}/unsafe-claim-target"
unsafe_claim_root="${test_dir}/unsafe-claim-root"
mkdir "${unsafe_claim_target}"
ln -s "${unsafe_claim_target}" "${unsafe_claim_root}"
set +e
unsafe_output="$(env PEIRATES_KIND_CLAIM_ROOT="${unsafe_claim_root}" bash -c '
    set -euo pipefail
    source "$1"
    claim=""
    acquire_kind_cluster_claim ownership-unsafe-root claim
' _ "${root_dir}/test/kind-build-helpers.sh" 2>&1)"
unsafe_status=$?
set -e
[[ "${unsafe_status}" == 1 ]]
[[ "${unsafe_output}" == *"not a safe directory"* ]]
[[ ! -e "${unsafe_claim_target}/ownership-unsafe-root" ]]

# A cleanup failure changes an otherwise successful local run to failure.
cleanup_log="${test_dir}/cleanup-success-delete-failure.log"
: >"${cleanup_log}"
set +e
cleanup_output="$(env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_CLAIM_ROOT="${claim_root}" \
    MOCK_SCENARIO=delete-failure MOCK_CLUSTER=ownership-cleanup-success \
    MOCK_LOG="${cleanup_log}" bash -c '
        set -euo pipefail
        source "$1"
        claim=""
        acquire_kind_cluster_claim ownership-cleanup-success claim
        cleanup_fixture() {
            finish_kind_script_cleanup "$?" ownership-cleanup-success "" owned "${claim}"
        }
        install_kind_script_traps cleanup_fixture
        exit 0
    ' _ "${root_dir}/test/kind-build-helpers.sh" 2>&1)"
cleanup_status=$?
set -e
[[ "${cleanup_status}" == 1 ]]
[[ "${cleanup_output}" == *"failed to delete owned Kind cluster"* ]]

run_signal_case() {
    local scenario="$1"
    local cluster="ownership-${scenario}"
    local log="${test_dir}/${scenario}.log"
    local output_file="${test_dir}/${scenario}.out"
    local setup_ready="${test_dir}/${scenario}-setup-ready"
    local delete_ready="${test_dir}/${scenario}-delete-ready"
    local delete_release="${test_dir}/${scenario}-delete-release"
    local delete_done="${test_dir}/${scenario}-delete-done"
    local status

    : >"${log}"
    env PATH="${mock_bin}:${PATH}" PEIRATES_KIND_CLAIM_ROOT="${claim_root}" \
        MOCK_SCENARIO="${scenario}" MOCK_CLUSTER="${cluster}" MOCK_LOG="${log}" \
        MOCK_SETUP_READY="${setup_ready}" MOCK_DELETE_READY="${delete_ready}" \
        MOCK_DELETE_RELEASE="${delete_release}" MOCK_DELETE_DONE="${delete_done}" \
        PEIRATES_EXEC_API_KIND_CLUSTER="${cluster}" \
        bash "${root_dir}/test/exec-via-api-kind-integration.sh" >"${output_file}" 2>&1 &
    active_pid=$!
    for _ in {1..400}; do [[ -e "${setup_ready}" ]] && break; sleep 0.01; done
    [[ -e "${setup_ready}" ]]
    kill -TERM "${active_pid}"
    if [[ "${scenario}" == signal-cleanup ]]; then
        for _ in {1..400}; do [[ -e "${delete_ready}" ]] && break; sleep 0.01; done
        [[ -e "${delete_ready}" ]]
        kill -TERM "${active_pid}"
        sleep 0.1
        kill -0 "${active_pid}"
        : >"${delete_release}"
    fi
    set +e
    wait "${active_pid}"
    status=$?
    set -e
    active_pid=""
    [[ "${status}" == 143 ]]
    [[ "$(count_log '^kind delete cluster ' "${log}")" == 1 ]]
    grep -Fxq "kind delete cluster --name ${cluster}" "${log}"
    [[ ! -e "${claim_root}/${cluster}" ]]
    if [[ "${scenario}" == signal-cleanup ]]; then
        [[ -e "${delete_done}" ]]
    fi
}

run_signal_case normal-signal
run_signal_case signal-cleanup

echo "Kind cluster ownership and cleanup regression tests passed"
