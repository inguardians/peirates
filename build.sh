#!/bin/sh

echo "Building..."
GOOS=linux GOARCH=amd64 go build -v ./cmd/peirates/peirates.go
echo "Final executable at $PWD/peirates"
