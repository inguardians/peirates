# Keep Go's build artifacts out of a developer's global cache by default.
# Override with `make test GOCACHE=/path/to/cache` when needed.
GOCACHE ?= /tmp/peirates-go-build
GOMODCACHE ?= /tmp/peirates-go-mod
PACKAGES = $(shell GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go list ./... | grep -v /vendor/)

KIND_TEST_CASES := \
	kind-test:KIND_CLUSTER_NAME:peirates-integration:test/kind-integration.sh \
	kubelet-kind-test:PEIRATES_KUBELET_KIND_CLUSTER:peirates-kubelet-integration:test/kubelet-kind-integration.sh \
	service-account-kind-test:PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER:peirates-service-account-integration:test/service-account-kind-integration.sh \
	namespace-kind-test:PEIRATES_NAMESPACE_KIND_CLUSTER:peirates-namespace-integration:test/namespace-kind-integration.sh \
	pod-info-kind-test:PEIRATES_POD_INFO_KIND_CLUSTER:peirates-pod-info-integration:test/pod-info-kind-integration.sh \
	volume-mount-kind-test:PEIRATES_VOLUME_MOUNT_KIND_CLUSTER:peirates-volume-mount-integration:test/volume-mount-kind-integration.sh \
	certificate-menu-kind-test:PEIRATES_CERTIFICATE_KIND_CLUSTER:peirates-certificate-integration:test/certificate-menu-kind-integration.sh \
	nodefs-steal-secrets-kind-test:PEIRATES_NODEFS_SECRETS_KIND_CLUSTER:peirates-nodefs-secrets-integration:test/nodefs-steal-secrets-kind-integration.sh \
	list-secrets-kind-test:PEIRATES_LIST_SECRETS_KIND_CLUSTER:peirates-list-secrets-integration:test/list-secrets-kind-integration.sh \
	secret-to-sa-kind-test:PEIRATES_SECRET_TO_SA_KIND_CLUSTER:peirates-secret-to-sa-integration:test/secret-to-sa-kind-integration.sh \
	attack-hostpath-kind-test:PEIRATES_ATTACK_HOSTPATH_KIND_CLUSTER:peirates-attack-hostpath-integration:test/attack-hostpath-kind-integration.sh \
	exec-via-api-kind-test:PEIRATES_EXEC_API_KIND_CLUSTER:peirates-exec-api-integration:test/exec-via-api-kind-integration.sh \
	kubectl-try-all-kind-test:PEIRATES_KUBECTL_TRY_ALL_KIND_CLUSTER:peirates-kubectl-try-all-integration:test/kubectl-try-all-kind-integration.sh \
	curl-kind-test:PEIRATES_CURL_KIND_CLUSTER:peirates-curl-integration:test/curl-kind-integration.sh
KIND_TEST_TARGETS := $(foreach test_case,$(KIND_TEST_CASES),$(word 1,$(subst :, ,$(test_case))))

.PHONY: default gofmt lint test test-quiet kind-kubeconfig-path-test kind-cluster-ownership-test kind-aggregate-test kind-test-inventory kind-tests $(KIND_TEST_TARGETS) update-deps

default: lint

gofmt:
	go fmt ./...

lint: gofmt
	$(GOPATH)/bin/golint $(PACKAGES)
	$(GOPATH)/bin/gosec -quiet -no-fail ./...
	$(GOPATH)/bin/golangci-lint run

test: kind-kubeconfig-path-test kind-cluster-ownership-test kind-aggregate-test
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -v ./...

test-quiet: kind-kubeconfig-path-test kind-cluster-ownership-test kind-aggregate-test
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

kind-kubeconfig-path-test:
	./test/kind-kubeconfig-path-test.sh

kind-cluster-ownership-test:
	./test/kind-cluster-ownership-test.sh

kind-aggregate-test:
	./test/kind-aggregate-test.sh

kind-test-inventory:
	@printf '%s\n' $(KIND_TEST_TARGETS)

kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/kind-integration.sh

kind-tests:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/run-kind-tests.sh $(KIND_TEST_CASES)

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

kubectl-try-all-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/kubectl-try-all-kind-integration.sh

curl-kind-test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) ./test/curl-kind-integration.sh

update-deps:
	go clean -modcache
	go get -u ./...
	go mod tidy
