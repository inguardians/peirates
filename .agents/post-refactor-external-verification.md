# Agent — Post-refactor external verification

## Goal

Run every verification check that was unavailable during the Peirates
reorganization, capture authoritative evidence, and write the results to
`docs/external-verification-results.md`.

## Scope and safety

This is a verification task, not a repair or release task. Do not change
production code, dependencies, scripts, Dockerfiles, deployment files, or test
expectations. Do not push images, publish artifacts, or test against a shared or
production Kubernetes cluster. If a check fails, preserve its output and report
the failure; request a separate fix goal.

Start by recording `git status --short`. Preserve every pre-existing change.
Use a workstation with network access, a working Docker daemon, Kind, kubectl,
Go 1.25.0, `docker-compose` (the legacy executable used by the Makefile), and
permission to create and delete a disposable Kind cluster.

## 1. Lint and security tools

Install `golint`, `gosec`, and `golangci-lint` into `$(go env GOPATH)/bin` if
they are absent. Record each tool's version and the exact install command and
version selected; do not modify `go.mod` or `go.sum` while installing tools.
Then run from the repository root:

```sh
make lint
git diff --check
git status --short
```

Confirm `make lint` did not introduce formatting changes. Record every warning
and distinguish tool/configuration failures from source findings. Note that the
Makefile intentionally invokes `gosec` with `-no-fail`; review its output even
when the target exits successfully.

## 2. Container builds and smoke test

Confirm daemon access with `docker info`, then run:

```sh
cd deployments
IMG_REPO=peirates-local IMG_REPO_DEV=peirates-dev-local make build dev
docker image inspect peirates-local:latest peirates-dev-local:latest
docker run --rm peirates-local:latest -c -m pwd
```

The production smoke test must exit without waiting for terminal input and show
the Peirates banner plus a working-directory result. Do not run `make push`,
`make push-dev`, or log in to a registry. Record image IDs, sizes, build exit
codes, and smoke-test output. Local images may be retained unless cleanup was
explicitly requested.

## 3. Disposable Kind integration test

Ensure no valuable cluster uses the default name `peirates-integration`.
Prefer an isolated name and run from the repository root:

```sh
KIND_CLUSTER_NAME=peirates-refactor-verification make kind-test
```

The script must create a disposable cluster, create its temporary namespace and
service account, pass `TestKindListsNamespaces`, and delete the cluster through
its cleanup trap. Afterward verify cleanup:

```sh
kind get clusters
```

If the cluster remains, report that clearly and delete only the exact
`peirates-refactor-verification` cluster.

## Deliverable

Create `docs/external-verification-results.md` containing:

- date, OS, architecture, and all relevant tool versions;
- the starting and ending `git status --short` output;
- each command, exit code, and concise result;
- relevant failure output with secrets and tokens redacted;
- confirmation that nothing was pushed or published;
- a final checklist marked pass, fail, or blocked for lint/security, production
  image, development image, container smoke test, Kind test, and cleanup.

Finish with `git diff --check`. A fully successful handoff has all checks marked
pass, no unexpected worktree changes, and no remaining disposable cluster.
