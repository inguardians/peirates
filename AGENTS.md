# Repository Guidelines

## Project Structure & Module Organization

Peirates is a Go-based Kubernetes penetration-testing CLI. The executable entry point is `cmd/peirates/peirates.go`, and application composition lives in `internal/app`. Shared types are in `internal/model`; UI, Kubernetes, cloud-provider, token, and local capability code lives in the corresponding `internal/ui`, `internal/kube`, `internal/cloud`, `internal/token`, and `internal/modules` packages. Unit tests sit beside their source as `*_test.go`. Integration tooling lives in `test/`, build and release helpers in `scripts/`, container definitions in `build/`, and Kubernetes/Docker assets in `deployments/`. Supporting documentation is in `docs/` and the root Markdown files.

## Build, Test, and Development Commands

- `go build ./cmd/peirates` builds the CLI for the current platform.
- `make build` creates a static Linux AMD64 `peirates` binary in the repository root; `make dist` builds the Linux distribution matrix.
- `make test` runs all Go tests verbosely; `make test-quiet` omits verbose output.
- `make lint` runs `go fmt`, `golint`, `gosec`, and `golangci-lint`; install those tools first.
- `make kind-test` runs the opt-in live Kubernetes integration test. It requires Docker, Kind, kubectl, and Go, and creates a disposable cluster.

The Makefile defaults Go caches to `/tmp`; override `GOCACHE` or `GOMODCACHE` when necessary.

## Coding Style & Naming Conventions

Use standard Go formatting and tabs as produced by `gofmt`; run `go fmt ./...` before submitting. Follow idiomatic Go naming: exported identifiers use `PascalCase`, internal identifiers use `camelCase`, and filenames use lowercase snake_case. Keep CLI wiring in `cmd/peirates`, orchestration in `internal/app`, and reusable behavior in the narrow internal package that owns it. Lower-level packages must not import `internal/app`. Handle errors explicitly and avoid introducing secrets, credentials, or cluster-specific values.

## Testing Guidelines

Use Go's `testing` package. Name files `*_test.go` and test functions `TestXxx`; prefer focused table-driven tests for multiple cases. Add regression tests beside the affected code. Run `make test-quiet` for every change and `make kind-test` when behavior depends on a live Kubernetes API. No numeric coverage threshold is documented, but new logic should exercise success and failure paths.

## Commit & Pull Request Guidelines

Recent history uses short, imperative or descriptive subjects such as `URL normalization fix` and `added kind-based tests`. Keep each commit focused and use a concise subject that states the change. Pull requests should explain the motivation and behavior change, list validation commands, and link relevant issues. Include terminal output or screenshots when CLI output changes. Clearly call out security implications, Kubernetes permissions, and any destructive test steps.
