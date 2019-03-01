#!/bin/sh

echo "Building..."
go build -v ./cmd/peirates/peirates.go
echo "Final executable at $PWD/peirates"
