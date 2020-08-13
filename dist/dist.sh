#!/bin/bash

build() {
    echo "$1"
    GOOS=linux GOARCH="$1" go build -i ../cmd/peirates
    mkdir peirates-linux-"$1"
    mv peirates peirates-linux-"$1"
    tar cJf peirates-linux-"$1".tar.xz peirates-linux-"$1"
    rm peirates-linux-"$1"/peirates
    rmdir peirates-linux-"$1"
}

if [ -z $1 ] ; then
    build amd64
    build arm
    build arm64
    build 386 
else
    build $1
fi
