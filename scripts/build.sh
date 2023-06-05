#!/usr/bin/env bash

# Email: peirates-dev <peirates-dev@inguardians.com>

# v0.2 - 08 May 2023 - Minor tweaks

# Additional flags added when compiling the binary if you wish to move onto a pod yourself using "kubectl cp" command or via wget if you can on a box
echo "Building for Linux on AMD64..."
GOOS=linux GOARCH=amd64 go build -v -ldflags="-s -w -linkmode 'external' -extldflags '-static'" $(realpath ../cmd/peirates)
exit_code=$?

if [ $exit_code -eq 0 ] ; then
  chmod 755 peirates
  mv peirates ..
  echo "Final executable at $(realpath ../peirates)"
  cat $(realpath ../peirates) | gzip -c > $(realpath ../peirates)
  exit 0
else
  exit $exit_code
fi
