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
