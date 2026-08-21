# Keep Go's build artifacts out of a developer's global cache by default.
# Override with `make test GOCACHE=/path/to/cache` when needed.
GOCACHE ?= /tmp/peirates-go-build
GOMODCACHE ?= /tmp/peirates-go-mod
PACKAGES := $(shell GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go list ./... | grep -v /vendor/)

.PHONY: default gofmt lint test test-quiet update-deps

default: lint

gofmt:
	go fmt ./...

lint: gofmt
	$(GOPATH)/bin/golint $(PACKAGES)
	$(GOPATH)/bin/gosec -quiet -no-fail ./...
	$(GOPATH)/bin/golangci-lint run

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -v ./...

test-quiet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...
	
update-deps:
	go clean -modcache
	go get -u ./...
	go mod tidy
