#!/usr/bin/env bash

# This shared test-support script builds Go packages that can run inside Kind
# nodes, regardless of the host machine's architecture.
#
# It provides support for:
# - Detecting a Kind node's machine architecture.
# - Mapping that architecture to the matching Go build target.
# - Cross-compiling arbitrary Go packages for a Kind node.
# - Building the Peirates CLI through the shared cross-compilation path.

# Keep the API server used by every Kind scenario on the same supported minor
# as Peirates' embedded kubectl client. Kind's release notes publish this exact
# multi-architecture image digest for v0.32.0.
PEIRATES_KIND_DEFAULT_NODE_IMAGE="kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"

kind_node_image() {
    printf '%s\n' "${PEIRATES_KIND_NODE_IMAGE:-${PEIRATES_KIND_DEFAULT_NODE_IMAGE}}"
}

# Compare assertions against raw output first, then use this exact replacement
# only for diagnostics. The token itself is never emitted by this helper.
redact_service_account_token_output() {
    local output="$1"
    local token="$2"

    if [[ -n "${token}" ]]; then
        output="${output//${token}/[REDACTED SERVICE ACCOUNT TOKEN]}"
    fi
    printf '%s\n' "${output}"
}

# Run a Kind test in a separate process group so INT and TERM can be forwarded
# to both the worker shell and whichever foreground command it is waiting for.
# Without this supervisor, Bash defers a trap while a foreground command is
# running, which can leave a signaled test waiting indefinitely.
run_kind_script_with_signal_forwarding() {
    local script="$1"
    shift

    if [[ "${PEIRATES_KIND_SIGNAL_WORKER:-}" == true ]]; then
        return
    fi

    local worker_pid=""
    local worker_status

    forward_kind_signal() {
        local signal="$1"
        local status="$2"

        # A second signal must not interrupt the worker's EXIT cleanup.
        trap '' INT TERM
        if [[ -n "${worker_pid}" ]]; then
            kill -s "${signal}" -- "-${worker_pid}" 2>/dev/null \
                || kill -s "${signal}" "${worker_pid}" 2>/dev/null \
                || true
            wait "${worker_pid}" 2>/dev/null || true
        fi
        exit "${status}"
    }

    # Bash cannot trap INT if a noninteractive parent started this supervisor
    # asynchronously with INT already ignored. Foreground INT and TERM are
    # handled here; callers that background a test should terminate it with
    # TERM instead of relying on a PID-directed INT.
    trap 'forward_kind_signal INT 130' INT
    trap 'forward_kind_signal TERM 143' TERM

    # Monitor mode gives the asynchronous worker its own process group. Disable
    # it again immediately so the supervisor itself retains ordinary scripting
    # behavior while it waits.
    set -m
    PEIRATES_KIND_SIGNAL_WORKER=true bash "${script}" "$@" &
    worker_pid=$!
    set +m

    if wait "${worker_pid}"; then
        worker_status=0
    else
        worker_status=$?
    fi
    trap - INT TERM
    exit "${worker_status}"
}

# Signals caught by the worker exit conventionally. Ignoring both signals
# before exit prevents another delivery from interrupting EXIT cleanup.
exit_kind_script_on_signal() {
    local status="$1"

    trap '' INT TERM
    exit "${status}"
}

install_kind_script_traps() {
    local cleanup_function="$1"

    trap "${cleanup_function}" EXIT
    trap 'exit_kind_script_on_signal 130' INT
    trap 'exit_kind_script_on_signal 143' TERM
}

# Serialize repository-owned Kind tests that use the same cluster name. The
# claim is deliberately advisory: a non-participating Kind process may still
# race us, so failed creation is never ownership proof by itself.
acquire_kind_cluster_claim() {
    local cluster_name="$1"
    local result_variable="$2"
    local claim_root="${PEIRATES_KIND_CLAIM_ROOT:-/tmp/peirates-kind-cluster-claims-${UID}}"
    local claim_key="${cluster_name//[^[:alnum:]._-]/_}"
    local claim_path="${claim_root}/${claim_key}"

    if [[ -L "${claim_root}" ||
        (-e "${claim_root}" && (! -d "${claim_root}" || ! -O "${claim_root}")) ]]; then
        echo "Kind cluster claim root is not a safe directory: ${claim_root}" >&2
        return 1
    fi
    if [[ ! -d "${claim_root}" ]]; then
        if ! (umask 077 && mkdir -- "${claim_root}") && [[ ! -d "${claim_root}" ]]; then
            echo "unable to create Kind cluster claim root: ${claim_root}" >&2
            return 1
        fi
    fi
    if [[ -L "${claim_root}" || ! -d "${claim_root}" || ! -O "${claim_root}" ]] ||
        ! chmod 700 -- "${claim_root}"; then
        echo "Kind cluster claim root is not an owned private directory: ${claim_root}" >&2
        return 1
    fi
    if ! mkdir -- "${claim_path}" 2>/dev/null; then
        echo "refusing Kind test for claimed cluster ${cluster_name}; another run may be active, or a stale claim at ${claim_path} requires manual inspection" >&2
        return 1
    fi
    printf -v "${result_variable}" '%s' "${claim_path}"
}

release_kind_cluster_claim() {
    local claim_path="$1"

    [[ -n "${claim_path}" ]] || return 0
    if ! rmdir -- "${claim_path}"; then
        echo "unable to release Kind cluster claim: ${claim_path}" >&2
        return 1
    fi
}

# Refuse an existing cluster and fail closed when Kind cannot enumerate names.
require_absent_kind_cluster() {
    local cluster_name="$1"
    local clusters

    if ! clusters="$(kind get clusters 2>&1)"; then
        echo "unable to enumerate Kind clusters; refusing to create ${cluster_name}" >&2
        [[ -z "${clusters}" ]] || printf '%s\n' "${clusters}" >&2
        return 1
    fi
    if grep -Fxq "${cluster_name}" <<<"${clusters}"; then
        echo "refusing to modify existing Kind cluster ${cluster_name}" >&2
        return 1
    fi
}

# A fresh private kubeconfig containing the expected context is durable
# provenance that this invocation progressed far enough to write cluster state.
kind_kubeconfig_proves_creation() {
    local cluster_name="$1"
    local kubeconfig_file="$2"
    local contexts

    [[ -s "${kubeconfig_file}" ]] || return 1
    if ! contexts="$(kubectl --kubeconfig "${kubeconfig_file}" config get-contexts -o name 2>/dev/null)"; then
        return 1
    fi
    grep -Fxq "kind-${cluster_name}" <<<"${contexts}"
}

create_kind_cluster_with_provenance() {
    local cluster_name="$1"
    local kubeconfig_file="$2"
    local state_variable="$3"
    local create_status
    shift 3

    printf -v "${state_variable}" '%s' creating
    if kind create cluster --name "${cluster_name}" --kubeconfig "${kubeconfig_file}" \
        --image "$(kind_node_image)" "$@"; then
        printf -v "${state_variable}" '%s' owned
        return 0
    else
        create_status=$?
    fi

    if kind_kubeconfig_proves_creation "${cluster_name}" "${kubeconfig_file}"; then
        printf -v "${state_variable}" '%s' partial-owned
        echo "Kind creation failed after writing private ownership provenance; cleanup will delete ${cluster_name}" >&2
    else
        printf -v "${state_variable}" '%s' ambiguous
        echo "Kind creation failed without ownership provenance; preserving any same-name resources for ${cluster_name}" >&2
    fi
    return "${create_status}"
}

cleanup_proven_kind_cluster() {
    local cluster_name="$1"
    local kubeconfig_file="$2"
    local ownership_state="$3"
    local delete_output

    case "${ownership_state}" in
        owned|partial-owned)
            ;;
        creating)
            if ! kind_kubeconfig_proves_creation "${cluster_name}" "${kubeconfig_file}"; then
                echo "Kind creation was interrupted without ownership provenance; preserving any same-name resources for ${cluster_name}" >&2
                return 0
            fi
            ;;
        none|ambiguous)
            return 0
            ;;
        *)
            echo "unknown Kind cluster ownership state: ${ownership_state}" >&2
            return 1
            ;;
    esac

    if ! delete_output="$(kind delete cluster --name "${cluster_name}" 2>&1)"; then
        echo "failed to delete owned Kind cluster ${cluster_name}" >&2
        [[ -z "${delete_output}" ]] || printf '%s\n' "${delete_output}" >&2
        return 1
    fi
}

# Finish an EXIT trap without allowing cleanup errors to turn success into a
# false positive. INT and TERM remain ignored for the entire cleanup, including
# child processes, so a second signal cannot strand an owned cluster.
finish_kind_script_cleanup() {
    local original_status="$1"
    local cluster_name="$2"
    local kubeconfig_file="$3"
    local ownership_state="$4"
    local claim_path="$5"
    local cleanup_failed=false
    local path
    shift 5

    trap - EXIT
    trap '' INT TERM
    if ! cleanup_proven_kind_cluster "${cluster_name}" "${kubeconfig_file}" "${ownership_state}"; then
        cleanup_failed=true
    fi
    if ! release_kind_cluster_claim "${claim_path}"; then
        cleanup_failed=true
    fi
    for path in "$@"; do
        if [[ -n "${path}" ]] && ! rm -f -- "${path}"; then
            echo "failed to remove Kind test temporary file: ${path}" >&2
            cleanup_failed=true
        fi
    done
    if [[ "${original_status}" == 0 && "${cleanup_failed}" == true ]]; then
        original_status=1
    fi
    exit "${original_status}"
}

canonicalize_kind_kubeconfig_path() {
    local candidate="$1"
    local directory
    local filename
    local canonical_directory

    if [[ -z "${candidate}" || "${candidate}" == *:* ||
        "${candidate}" == *$'\n'* || "${candidate}" == *$'\r'* ]]; then
        echo "manual kubeconfig override must be one unambiguous filesystem path" >&2
        return 1
    fi

    if [[ "${candidate}" == */* ]]; then
        directory="${candidate%/*}"
        filename="${candidate##*/}"
        [[ -n "${directory}" ]] || directory="/"
    else
        directory="."
        filename="${candidate}"
    fi
    if [[ -z "${filename}" || "${filename}" == "." || "${filename}" == ".." ||
        ! -d "${directory}" ]]; then
        echo "manual kubeconfig override must have an existing parent directory" >&2
        return 1
    fi

    canonical_directory="$(cd -- "${directory}" && pwd -P)" || return 1
    printf '%s/%s\n' "${canonical_directory%/}" "${filename}"
}

# Detect the Kind node architecture and expose its corresponding Go target.
kind_node_go_target() {
    local node_name="$1"
    local machine

    machine="$(docker exec "${node_name}" uname -m)"
    KIND_NODE_GOARM=""
    case "${machine}" in
        x86_64|amd64)
            KIND_NODE_GOARCH="amd64"
            ;;
        aarch64|arm64)
            KIND_NODE_GOARCH="arm64"
            ;;
        armv6l)
            KIND_NODE_GOARCH="arm"
            KIND_NODE_GOARM="6"
            ;;
        armv7l|armv8l)
            KIND_NODE_GOARCH="arm"
            KIND_NODE_GOARM="7"
            ;;
        i386|i486|i586|i686)
            KIND_NODE_GOARCH="386"
            ;;
        ppc64le|riscv64|s390x)
            KIND_NODE_GOARCH="${machine}"
            ;;
        *)
            echo "unsupported Kind node architecture: ${machine}" >&2
            return 1
            ;;
    esac
}

# Cross-compile the requested Go package for the detected Kind node target.
build_go_package_for_kind_node() {
    local root_dir="$1"
    local output_path="$2"
    local node_name="$3"
    local package="$4"

    kind_node_go_target "${node_name}"
    if [[ -n "${KIND_NODE_GOARM}" ]]; then
        (cd "${root_dir}" && CGO_ENABLED=0 GOOS=linux GOARCH="${KIND_NODE_GOARCH}" \
            GOARM="${KIND_NODE_GOARM}" go build -o "${output_path}" "${package}")
    else
        (cd "${root_dir}" && CGO_ENABLED=0 GOOS=linux GOARCH="${KIND_NODE_GOARCH}" \
            go build -o "${output_path}" "${package}")
    fi
}

# Build the Peirates executable using the shared node-aware build helper.
build_peirates_for_kind_node() {
    build_go_package_for_kind_node "$1" "$2" "$3" ./cmd/peirates
}
