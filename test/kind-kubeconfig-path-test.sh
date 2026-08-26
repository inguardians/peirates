#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"

test_dir="$(mktemp -d /tmp/peirates-kind-kubeconfig-path-test.XXXXXX)"
cleanup() {
    rm -rf "${test_dir}"
}
trap cleanup EXIT

mkdir -p "${test_dir}/physical/subdirectory"
ln -s "${test_dir}/physical" "${test_dir}/link"

relative_path="$(
    cd "${test_dir}"
    canonicalize_kind_kubeconfig_path "link/subdirectory/../retained.conf"
)"
if [[ "${relative_path}" != "${test_dir}/physical/retained.conf" ]]; then
    echo "relative kubeconfig path was not canonicalized through its physical parent" >&2
    exit 1
fi

absolute_candidate="${test_dir}/physical/absolute.conf"
absolute_path="$(canonicalize_kind_kubeconfig_path "${absolute_candidate}")"
if [[ "${absolute_path}" != "${absolute_candidate}" ]]; then
    echo "absolute kubeconfig path changed unexpectedly" >&2
    exit 1
fi

sentinel_one="${test_dir}/sentinel-one"
sentinel_two="${test_dir}/sentinel-two"
printf 'sentinel one\n' >"${sentinel_one}"
printf 'sentinel two\n' >"${sentinel_two}"
sentinel_one_hash="$(sha256sum "${sentinel_one}" | awk '{print $1}')"
sentinel_two_hash="$(sha256sum "${sentinel_two}" | awk '{print $1}')"

invalid_paths=(
    "${sentinel_one}:${sentinel_two}"
    $'newline\npath'
    $'return\rpath'
    "${test_dir}/missing/retained.conf"
    "${test_dir}/physical/"
)
for invalid_path in "${invalid_paths[@]}"; do
    if canonicalize_kind_kubeconfig_path "${invalid_path}" >/dev/null 2>&1; then
        echo "invalid kubeconfig path was accepted" >&2
        exit 1
    fi
done

if [[ "$(sha256sum "${sentinel_one}" | awk '{print $1}')" != "${sentinel_one_hash}" ||
    "$(sha256sum "${sentinel_two}" | awk '{print $1}')" != "${sentinel_two_hash}" ]]; then
    echo "path validation modified a supplied kubeconfig sentinel" >&2
    exit 1
fi

echo "Kind kubeconfig path validation passed"
