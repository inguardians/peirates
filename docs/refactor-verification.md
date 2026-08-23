# Reorganization Verification

## Baseline

Before production files moved, Go 1.25.0 matched `go.mod`, and `gofmt`,
`go vet ./...`, `go test ./...`, and `go build ./cmd/peirates` passed. The
existing checksum set was generated from pinned module versions without
changing `go.mod`; `go.sum` is now tracked instead of ignored.

## Completed checks

- `go test ./...` and `make test-quiet`
- `go test -race ./...`
- `go vet ./...` and a clean `gofmt` check
- integration-tag compile: `go test -run '^$' -tags=integration ./...`
- normal build: `go build ./cmd/peirates`
- static build: `(cd scripts && ./build.sh)`
- Linux cross-builds for `amd64`, `arm`, `arm64`, and `386`
- `git diff --check` and dependency/script/deployment diff review

## Environment-dependent checks

The current environment has Docker and Kind clients but cannot access the
Docker daemon, and kubectl is unavailable. Run these checks on a workstation
with Docker daemon access, Kind, and kubectl:

```sh
make kind-test
cd deployments
IMG_REPO=peirates-local IMG_REPO_DEV=peirates-dev-local make build dev
```

The project lint/security executables (`golint`, `gosec`, and
`golangci-lint`) are not installed in the current environment. After installing
the configured tools, run `make lint`. No artifacts were published.


## Pragmatic package boundaries

Kubelet `/proc` discovery and key/certificate loading remain in `internal/app`
because extracting that sensitive filesystem behavior was rejected by the
workspace safety layer. Interactive AWS/GCP attack flows, curl orchestration,
and attack modules also remain cohesive with app composition because splitting
their current callbacks and session mutations would introduce cycles or alter
observable prompts. Their pure metadata, transport, token, filesystem, DNS,
portscan, and shell boundaries are extracted and independently tested. The
legacy `Verbose` variable remains as a narrow compatibility seam for these
unchanged routines; all other broad runtime state is held by `app.Session`.
