#!/bin/bash

# Email: peirates-dev <peirates-dev@inguardians.com>

# v0.2 - 13 May 2023 - Updates to script

declare -a ARCHITECTURES=( "amd64" "arm" "arm64" "386" )

OS="linux"
ARCH="amd64"
COMPRESS="yes" # unused right now. Who uses this functionality?

function usage() {
  echo "Dist script: Build for multiple distros."
  echo
  echo "Syntax: dist.sh [-a|-m|-r|-t|-x]"
  echo "options:"
  echo "-h     Print this Help."
  echo "-a     Build for amd64"
  echo "-m     Build for arm"
  echo "-r     Build for arm64"
  echo "-t     Build for 386"
  echo "-x     Build all architectures"
}

function compress() {
  tar cJf peirates-${OS}-${ARCH}.tar.xz peirates-${OS}-${ARCH}
  rm peirates-${OS}-${ARCH}/peirates
  rmdir peirates-${OS}-${ARCH}
}

function build() {
  echo "Building for arch: ${ARCH}"
  GOOS=${OS} GOARCH=${ARCH} go build -ldflags="-s -w" $(realpath ../cmd/peirates)
  mkdir peirates-${OS}-${ARCH}
  mv peirates peirates-${OS}-${ARCH}
  compress ${ARCH}
}

function main() {  
  for xx in ${ARCHITECTURES[@]};
  do
    ARCH="${xx}"
    build ${ARCH}
  done
}

while getopts "hamrtx" option; do
  case $option in
    h)
      usage
      exit 0
    ;;
    a)
      ARCHITECTURES=( "amd64" )
      main
      exit 0
    ;;
    m)
      ARCHITECTURES=( "arm" )
      main
      exit 0
    ;;
    r)
      ARCHITECTURES=( "arm64" )
      main
      exit 0
    ;;
    t)
      ARCHITECTURES=( "386" )
      main
      exit 0
    ;;
    x)
      main
      exit 0
    ;;
    \?)
      usage
      exit 1
    ;;
  esac
done

if [ "$option" = "?" ]; then
  usage && exit 1
fi