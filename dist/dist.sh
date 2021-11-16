#!/bin/bash

compress() {
    tar cJf peirates-linux-"$1".tar.xz peirates-linux-"$1"
    rm peirates-linux-"$1"/peirates
    rmdir peirates-linux-"$1"
}

build() {
    echo "$1"
    arch=$1

    GOOS=linux GOARCH="$arch" go build -i ../cmd/peirates
    mkdir peirates-linux-"$1"
    mv peirates peirates-linux-"$1"

    if  [ $COMPRESS == "yes" ] ; then
       compress $arch
    fi

}

COMPRESS=yes
if [ "$2" = "buildonly" ] ; then
    COMPRESS=no
fi

if [ -z $1 ] ; then
    for arch in amd64 arm arm64 386 ; do
       build $arch
    done
else
    build $1
fi

