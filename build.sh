#!/bin/sh

echo "Building for Linux on AMD64..."
GOOS=linux GOARCH=amd64 go build -v -ldflags="-s -w" ./cmd/peirates
exit_code=$?

if [ $exit_code -eq 0 ] ; then
    echo "Final executable at $PWD/peirates with gzipped compressed version at peirates.gz"
    cat peirates | gzip -c >peirates.gz
    chmod 755 $PWD/peirates
    exit 0
else
    exit $exit_code
fi
