# Keep Go's build artifacts out of a developer's global cache by default.
# Override with `make test GOCACHE=/path/to/cache` when needed.
GOCACHE ?= /tmp/peirates-go-build
GOMODCACHE ?= /tmp/peirates-go-mod
PACKAGES := $(shell GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go list ./... | grep -v /vendor/)

.PHONY: default gofmt lint test test-quiet kind-test kubelet-kind-test service-account-kind-test namespace-kind-test pod-info-kind-test volume-mount-kind-test certificate-menu-kind-test nodefs-steal-secrets-kind-test list-secrets-kind-test secret-to-sa-kind-test attack-hostpath-kind-test exec-via-api-kind-test update-deps

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

kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/kind-integration.sh

kubelet-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/kubelet-kind-integration.sh

service-account-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/service-account-kind-integration.sh

namespace-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/namespace-kind-integration.sh

pod-info-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/pod-info-kind-integration.sh

volume-mount-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/volume-mount-kind-integration.sh

certificate-menu-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/certificate-menu-kind-integration.sh

nodefs-steal-secrets-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/nodefs-steal-secrets-kind-integration.sh

list-secrets-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/list-secrets-kind-integration.sh

secret-to-sa-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/secret-to-sa-kind-integration.sh

attack-hostpath-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/attack-hostpath-kind-integration.sh

exec-via-api-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/exec-via-api-kind-integration.sh

update-deps:
	go clean -modcache
	go get -u ./...
	go mod tidy
