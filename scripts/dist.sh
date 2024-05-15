#!/bin/bash

# Email: peirates-dev <peirates-dev@inguardians.com>

# v0.2 - 13 May 2023 - Updates to script

declare -a ARCHITECTURES=( "amd64" "arm" "arm64" "386" )

OS="linux"
ARCH="amd64"
COMPRESS="yes"

function usage() {
  echo "Dist script: Build for multiple distros."
  echo
  echo "Syntax: dist.sh [-a|-c|-m|-r|-t|-x]"
  echo "options:"
  echo "-h     Print this Help."
  echo "-a     Build for amd64"
  echo "-C     Do not compress binaries after building"
  echo "-m     Build for arm"
  echo "-r     Build for arm64"
  echo "-t     Build for 386"
  echo "-x     Build all architectures"
  echo "-s     Build statically-linked"
}

function compress() {
  tar cJf peirates-${OS}-${ARCH}.tar.xz peirates-${OS}-${ARCH}
  rm peirates-${OS}-${ARCH}/peirates
  rmdir peirates-${OS}-${ARCH}
}

function build() {
  echo "Building for arch: ${ARCH}"

  if [ $STATIC == "static" ] ; then
     GOOS=${OS} GOARCH=${ARCH} go build -tags netgo,osusergo --ldflags '-extldflags "-static"' $(realpath ../cmd/peirates)
  else
     GOOS=${OS} GOARCH=${ARCH} go build -ldflags="-s -w" $(realpath ../cmd/peirates)
  fi

  if [ ! -d peirates-${OS}-${ARCH} ] ; then
    mkdir peirates-${OS}-${ARCH}
  fi
  mv peirates peirates-${OS}-${ARCH}
  if [ $COMPRESS == "yes" ] ; then
    compress ${ARCH}
  fi
}

function main() {  
  if [ ! -e ../cmd/peirates ] ; then
    echo "This script must be run from the scripts/ directory."
    exit 1
  fi

  for xx in ${ARCHITECTURES[@]};
  do
    ARCH="${xx}"
    #build-dynamic ${ARCH}
    build ${ARCH}
  done
}

STATIC="dynamic"

while getopts "haCmrstx" option; do
  case $option in
    h)
      usage
      exit 0
    ;;
    a)
      ARCHITECTURES=( "amd64" )
    ;;
    C)
      COMPRESS="no"
    ;;
    m)
      ARCHITECTURES=( "arm" )
    ;;
    r)
      ARCHITECTURES=( "arm64" )
    ;;
    s)
      STATIC="static"
    ;;
    t)
      ARCHITECTURES=( "386" )
    ;;
    x)
      true
    ;;
    \?)
      usage
      exit 1
    ;;
  esac
done

main
exit 0

if [ "$option" = "?" ]; then
  usage && exit 1
fi
