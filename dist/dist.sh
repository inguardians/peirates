#!/bin/bash

build() {
    echo "$1"
    GOOS=linux GOARCH="$1" go build ../cmd/peirates
    mkdir peirates-linux-"$1"
    mv peirates peirates-linux-"$1"
    tar cJf peirates-linux-"$1".tar.xz peirates-linux-"$1"
    rm peirates-linux-"$1"/peirates
    rmdir peirates-linux-"$1"
}

build amd64
build arm
build arm64
build 386
