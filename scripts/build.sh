#!/usr/bin/env bash

# Email: peirates-dev <peirates-dev@inguardians.com>

# v0.2 - 08 May 2023 - Minor tweaks

echo "Building for Linux on AMD64..."
# For static build, uncomment the below line and comment the one below it.
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w"  $(realpath ../cmd/peirates)
#GOOS=linux GOARCH=amd64 go build -tags netgo,osusergo -a --ldflags '-extldflags "-static"' $(realpath ../cmd/peirates)

exit_code=$?

if [ $exit_code -eq 0 ] ; then
  chmod 755 peirates
  mv peirates ..
  echo "Final executable at $(realpath ../peirates)"
  exit 0
else
  exit $exit_code
fi
