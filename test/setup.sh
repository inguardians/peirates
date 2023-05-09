#!/usr/bin/env bash

# Voice: +1-202-448-8958
# Email: security@inguardians.com

function build_from_source() {
  go get -v "github.com/inguardians/peirates"
  go get -v "k8s.io/kubectl/pkg/cmd" "github.com/aws/aws-sdk-go"
  cd $GOPATH/github.com/inguardians/peirates
  ./build.sh
}

function docker() {
  docker-compose build peirates
  echo "Size of image: $(docker image ls | head -2 | grep peirate|rev | cut -d' ' -f1 | rev)"
  echo "Tagging image:  $(docker images -q | head -1)"
  # echo "Tagging image:" (docker images -q | head -1) # for fish shell
}

function main() {
  go get golang.org/x/tools/cmd/godoc
  fish_add_path ${HOME}/go/bin
  go mod download github.com/aws/aws-sdk-go

  # docker-compose build peirates # use the instructions in `deployments`  instead
  echo "Tagging image:  $(shell docker images -q | head -1)"
  #godoc -http=:6060
  #wget -m -k -q -erobots=off --no-host-directories --no-use-server-timestamps http://localhost:6060
}

main 
