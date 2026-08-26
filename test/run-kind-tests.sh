#!/usr/bin/env bash
# Run the complete Kind inventory serially and verify exact-name cleanup after
# every scenario. The case records are target:cluster-env:default-name:script.
set -uo pipefail

if (($# == 0)); then
    echo "Kind aggregate runner requires at least one test case" >&2
    exit 2
fi

for test_case in "$@"; do
    IFS=: read -r target cluster_variable default_cluster script extra <<<"${test_case}"
    if [[ -z "${target}" || -z "${cluster_variable}" || -z "${default_cluster}" ||
        -z "${script}" || -n "${extra}" ]]; then
        echo "invalid Kind aggregate case: ${test_case}" >&2
        exit 2
    fi
    if [[ ! "${cluster_variable}" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
        echo "invalid Kind cluster environment variable for ${target}: ${cluster_variable}" >&2
        exit 2
    fi
    if [[ ! -x "${script}" ]]; then
        echo "Kind test script is not executable for ${target}: ${script}" >&2
        exit 2
    fi

    cluster_name="${!cluster_variable:-${default_cluster}}"
    printf '\n==> Running %s with disposable cluster %s\n' "${target}" "${cluster_name}"

    if env "${cluster_variable}=${cluster_name}" "${script}"; then
        test_status=0
    else
        test_status=$?
        printf '==> %s failed with exit status %s\n' "${target}" "${test_status}" >&2
    fi

    if ! clusters="$(kind get clusters 2>&1)"; then
        echo "==> unable to enumerate Kind clusters after ${target}; cleanup is unverified" >&2
        [[ -z "${clusters}" ]] || printf '%s\n' "${clusters}" >&2
        if ((test_status != 0)); then
            exit "${test_status}"
        fi
        exit 1
    fi
    if grep -Fxq "${cluster_name}" <<<"${clusters}"; then
        echo "==> exact cleanup failed after ${target}; cluster remains: ${cluster_name}" >&2
        if ((test_status != 0)); then
            exit "${test_status}"
        fi
        exit 1
    fi
    printf '==> Verified absent after %s: %s\n' "${target}" "${cluster_name}"

    if ((test_status != 0)); then
        exit "${test_status}"
    fi
done

echo "All Kind integration targets passed with exact-name cleanup verified"
