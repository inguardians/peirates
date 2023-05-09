#!/usr/bin/env bash

# Voice: +1-202-448-8958
# Email: security@inguardians.com

# v0.2 - 08 May 2023 - Minor tweaks

echo "Building for Linux on AMD64..."
GOOS=linux GOARCH=amd64 go build -v -ldflags="-s -w" ../cmd/peirates
exit_code=$?

if [ $exit_code -eq 0 ] ; then
  chmod 755 peirates
  mv peirates ..
  echo "Final executable at $PWD/peirates"
  cat ../peirates | gzip -c >../peirates.gz
  exit 0
else
  exit $exit_code
fi
