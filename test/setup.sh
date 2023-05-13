#!/usr/bin/env bash

# Email: peirates-dev <peirates-dev@inguardians.com>

CURRENT_DIR=$(realpath .)

function install_deps() {
  echo "☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Install dependencies..."
  go get golang.org/x/tools/cmd/godoc
  go mod download github.com/aws/aws-sdk-go
}

function build_from_source() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Build from source..."
  go get -v "github.com/inguardians/peirates"
  go get -v "k8s.io/kubectl/pkg/cmd" "github.com/aws/aws-sdk-go"
  cd ${CURRENT_DIR}/../scripts && ./build.sh # is this right? 
}

function docker() {  
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Docker build..."
  cd ${CURRENT_DIR}/../deployments && docker-compose build peirates
  echo "Size of image: $(docker image ls | head -2 | grep peirate|rev | cut -d' ' -f1 | rev)"
  echo "Tagging image:  $(docker images -q | head -1)"
  # echo "Tagging image:" (docker images -q | head -1) # for fish shell
}

function security() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "GoSec Security Checks..."
  cd ${CURRENT_DIR}/.. && gosec -conf test/.gosec.config.json -track-suppressions ./...
}

function main() {

  install_deps
  security 
  docker

  # Is this useful? 
  #godoc -http=:6060
  #wget -m -k -q -erobots=off --no-host-directories --no-use-server-timestamps http://localhost:6060
}

main 
