# Test

## Dependencies

Run `go mod tidy -e` to keep things up to date.

To test the dependencies:

```sh
go list -u -m all # view available minor and patch upgrades for all direct and indirect dependencies
go get -u ./... # upgrades to the latest or minor patch release
go get -t -u ./... # upgrade test dependencies
go test all # run the following command to test that packages are working correctly after an upgrade
```

Additional external test apps and test data.

## Setup

* Install `direnv`

```sh
direnv allow .
```

## Container

* Use these steps to create the container images.
* Go to your packages on Github to verify everything is working.

```sh
cd deployments
make build
make push
make dev
make push-dev
```

## Kind integration test

This opt-in test creates a disposable Kind cluster, grants a temporary service
account read access, and verifies Peirates can list namespaces through the
live Kubernetes API. It requires Docker, Kind, kubectl, and Go.

```sh
make kind-test
```

## Security

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# machine readable
# gosec -conf test/.gosec.config.json -track-suppressions -fmt=json -out=test/results.json -stdout ./...
gosec -conf test/.gosec.config.json -track-suppressions ./...
```

Govulncheck

```sh
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
# Run govulncheck
govulncheck ./...
```

## Service-account menu integration test

Run `make service-account-kind-test` to create a disposable Kind cluster and
exercise all seven actions under main-menu option 1 through a Peirates binary
running in a pod: list, switch, add, export, import, decode, and display. The
test uses the pod's real projected service-account JWT, refuses to modify a
pre-existing cluster named `peirates-service-account-integration`, and deletes
the disposable cluster on exit. Override the cluster name with
`PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER`, using a name reserved for this test.

The raw-token display assertion handles a token belonging only to the
disposable cluster; the token stops being useful when cleanup deletes it.


## Namespace menu integration test

Run `make namespace-kind-test` to create a disposable Kind cluster and exercise
both actions under main-menu option 2 through a Peirates binary running in a
pod: list namespaces and switch namespace. The pod's default service account is
granted only `get` and `list` on core `namespaces`. The test refuses to modify a
pre-existing cluster named `peirates-namespace-integration` and deletes its
disposable cluster on exit. Override the name with
`PEIRATES_NAMESPACE_KIND_CLUSTER`, using a name reserved for this test.

## Pod information integration test

Run `make pod-info-kind-test` to create a disposable Kind cluster and exercise
main-menu item 3 (list pods) followed by item 4 (dump complete pod JSON) through
a Peirates binary running in a pod. The pod's default service account is granted
only namespace-scoped `get` and `list` access to core `pods`. The test refuses to
modify a pre-existing cluster named `peirates-pod-info-integration` and deletes
only its dedicated cluster on exit. Override the name with
`PEIRATES_POD_INFO_KIND_CLUSTER`, using a name reserved for this test.

## Anonymous kubelet integration test

Run `make kubelet-kind-test` to create a disposable Kind cluster and prove that
Peirates can list running pods through the unauthenticated read-only kubelet endpoint on port 10255 and execute a command through the anonymous HTTPS kubelet endpoint on port 10250. The test
refuses to use a pre-existing cluster, uses the isolated cluster name
`peirates-kubelet-integration` by default, and deletes that cluster on every exit. The namespace default service account is granted only `get` and `list` on core `nodes`, and setup verifies that permission. It also receives namespace-scoped pod `get`/`list` plus the legacy pod `exec` authorization verb and `pods/exec` `create` permissions so the test can copy Peirates into the target pod and run its `exec-via-api` all-pods path with `id`.
Override the name with `PEIRATES_KUBELET_KIND_CLUSTER`; choose a name reserved for
this disposable test.

This test intentionally configures the disposable node kubelet with anonymous authentication, `AlwaysAllow` authorization, and the read-only port. Those settings permit unauthenticated pod discovery and command execution and are unsafe for any
shared or persistent cluster. The test must never be adapted to target an existing
cluster. Docker, Kind, kubectl, Go, and network access to pull the test image are
required.
