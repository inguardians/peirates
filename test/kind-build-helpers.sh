#!/usr/bin/env bash

# This shared test-support script builds Go packages that can run inside Kind
# nodes, regardless of the host machine's architecture.
#
# It provides support for:
# - Detecting a Kind node's machine architecture.
# - Mapping that architecture to the matching Go build target.
# - Cross-compiling arbitrary Go packages for a Kind node.
# - Building the Peirates CLI through the shared cross-compilation path.

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
