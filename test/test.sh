#!/usr/bin/env bash

# This development test runner prepares dependencies, builds Peirates, and provides
# checks for the application, its container image, security posture, and documentation.
#
# It can run:
# - Development dependency installation.
# - A source build of the Peirates binary.
# - A Docker image build with image metadata logging.
# - GoSec security checks.
# - Go module upgrade checks and the Go test suite.
# - A local Go documentation server and documentation mirror.

# Email: peirates-dev <peirates-dev@inguardians.com>

# v0.1 - 08 May 2023 - Initial Version

# Resolve output paths from the directory where the runner was invoked.
CURRENT_DIR=$(realpath .)
DOCKER_LOG="${CURRENT_DIR}/docker-testing.log"
SECURITY_LOG="${CURRENT_DIR}/security-testing.log"
TEST_LOG="${CURRENT_DIR}/app-testing.log"

# Install development dependencies used by the remaining runner actions.
function install_deps() {
  echo "☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Install dependencies..."
  go get golang.org/x/tools/cmd/godoc
  go mod download github.com/aws/aws-sdk-go
}

# Fetch project build dependencies and invoke the repository build target.
function build_from_source() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Build from source..."
  go get -v "github.com/inguardians/peirates"
  go get -v "k8s.io/kubectl/pkg/cmd" "github.com/aws/aws-sdk-go"
  make -C "${CURRENT_DIR}/.." build
}

# Build the container image and record its resulting metadata.
function docker() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️" | tee ${DOCKER_LOG}
  echo "Docker build..." | tee -a ${DOCKER_LOG}
  cd ${CURRENT_DIR}/../deployments && docker-compose build peirates | -a tee ${DOCKER_LOG}
  echo "Size of image: $(docker image ls | head -2 | grep peirate|rev | cut -d' ' -f1 | rev)" | tee -a ${DOCKER_LOG}
  echo "Tagging image:  $(docker images -q | head -1)" | tee -a ${DOCKER_LOG}
  # echo "Tagging image:" (docker images -q | head -1) # for fish shell
}

# Run GoSec against the repository and capture its findings.
function security() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️" | tee ${SECURITY_LOG}
  echo "GoSec Security Checks..." | tee -a ${SECURITY_LOG}
  cd ${CURRENT_DIR}/.. && gosec -conf ${CURRENT_DIR}/.gosec.config.json -track-suppressions ./... 2>&1 | tee -a ${SECURITY_LOG}
}

# Check module upgrades and run the Go package test suite.
function test_all() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️" | tee ${TEST_LOG}
  echo "testing..." | tee -a ${TEST_LOG}
  echo "" | tee -a ${TEST_LOG}
  echo "view available minor and patch upgrades for all direct and indirect dependencies" | tee -a ${TEST_LOG}
  cd ${CURRENT_DIR}/.. && go list -u -m all 2>&1 | tee -a ${TEST_LOG}
  echo "upgrades to the latest or minor patch release" | tee -a ${TEST_LOG}
  cd ${CURRENT_DIR}/.. && go get -u ./... 2>&1 | tee -a ${TEST_LOG}
  echo "upgrade test dependencies" | tee -a ${TEST_LOG}
  cd ${CURRENT_DIR}/.. && go get -t -u ./... 2>&1 | tee -a ${TEST_LOG}
  echo "test that packages are working correctly after an upgrade" | tee -a ${TEST_LOG}
  cd ${CURRENT_DIR}/.. && go test all 2>&1 | tee -a ${TEST_LOG}
}

# Serve local Go documentation and mirror it for offline inspection.
function godoc() {
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  echo "Godoc..."
  godoc -http=:6060
  get -m -k -q -erobots=off --no-host-directories --no-use-server-timestamps http://localhost:6060
}

# Select the development checks run by default.
function main() {
  install_deps
  security
  test_all
  #docker
  #docker system prune -f # clean up the local disk
  #godoc
}

# Enter the test runner.
main
