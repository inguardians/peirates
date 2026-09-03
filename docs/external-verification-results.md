# External Verification Results

Date: 2026-08-23
Host: Ubuntu Linux 6.8.0-138-generic, `linux/amd64`

## Environment

| Tool | Version |
| --- | --- |
| Go | `go1.25.0 linux/amd64` |
| golint | `golang.org/x/lint@v0.0.0-20241112194109-818c5a804067` |
| gosec | `v2.22.2`, built with Go 1.26.7 (`-version` reports `dev`) |
| golangci-lint | `v1.64.8`, built with Go 1.26.7 |
| Docker client/server | `29.7.2` |
| Docker Compose plugin | `v5.5.0` |
| Kind | `v0.32.0` |
| kubectl | client `v1.36.4`, Kustomize `v5.8.1` |

The verifier binaries were installed outside the repository in
`/home/jay/go/bin`. Commands used were:

```sh
go install golang.org/x/lint/golint@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@v2.22.2
```

The initial attempt to install `gosec@latest` resolved to v2.28.0, required Go
1.26.7, and was stopped after more than 20 minutes of compiling its expanded
dependency graph. Version 2.22.2 was then selected explicitly and installed.
Repository module files were unchanged: their starting and ending SHA-256
values were `ddd1bb2d...e01a0` for `go.mod` and
`87506d74...b5b8` for `go.sum`.

## Starting worktree

Exact starting `git status --short` output (the report itself already existed):

```text
 M .gitignore
 D attack_create_hostfs_pod.go
 D aws.go
 D aws_test.go
 D cloud_detection.go
 D cloud_detection_test.go
 M cmd/peirates/peirates.go
 D commandline.go
 D config.go
 D config_output_node_test.go
 D curl.go
 D cve-2024-21626.go
 D decode_jwt.go
 D decode_jwt_test.go
 D enumerate_dns.go
 D enumerate_simple_objects.go
 D enumerate_simple_objects_test.go
 D exec_in_pods.go
 D exec_via_kubelet_api.go
 D filesystem_manipulation.go
 D filesystem_manipulation_test.go
 D gcp.go
 D gcp_test.go
 D http_utils.go
 D inject-into-pod-alpha.go
 D json_structs.go
 D kind_integration_test.go
 D kubeapi.go
 D kubectl_interactive.go
 D kubectl_wrappers.go
 D list_secrets.go
 D menu.go
 D menu_cert_auth.go
 D menu_namespaces.go
 D menu_serviceaccounts.go
 D menu_tcp_portscan.go
 D menu_use_auth_cani.go
 D misc_utils.go
 D misc_utils_test.go
 D module_commands_test.go
 D module_dispatch.go
 D node_secrets.go
 D output_to_user.go
 D peirates.go
 D portscan.go
 D portscan_test.go
 D run_external_programs.go
 D run_external_programs_test.go
 D service_account_utils.go
 D service_account_utils_test.go
 D transport_test.go
?? .agents/
?? AGENTS.md
?? docs/architecture.md
?? docs/external-verification-results.md
?? docs/refactor-verification.md
?? go.sum
?? internal/
?? plan.txt
```

`git status --short` showed the expected in-progress reorganization: modified
`.gitignore` and `cmd/peirates/peirates.go`; deletion of the former root-level
Go implementation and test files; and untracked `.agents/`, `AGENTS.md`,
`go.sum`, `internal/`, `plan.txt`, `docs/architecture.md`, and
`docs/refactor-verification.md`, and the pre-existing `docs/external-verification-results.md`. These changes were preserved.

## Lint and security

The current literal `make lint` exited 2 because the Makefile expands the shell
variable `$GOPATH`, which was unset, and attempted `/bin/golint`. The target was
rerun as:

```sh
GOPATH=/home/jay/go make lint
```

This ran all three configured tools but exited 2 at golangci-lint:

- `golint`: 100 findings, primarily exported-symbol comments, initialism/name
  conventions, and redundant `else` blocks.
- `gosec -quiet -no-fail ./...`: 26 findings. These included three
  high-confidence `G402` insecure-TLS findings, two low-confidence `G101`
  credential false positives, command-execution findings expected for this
  penetration-testing CLI, variable-path file access, and unchecked errors.
  `-no-fail` means these did not determine the target's exit status.
- `golangci-lint`: 20 findings across `errcheck`, `unused`, `gosimple`,
  `ineffassign`, and `staticcheck`.

An additional `/home/jay/go/bin/golangci-lint run --timeout=10m` completed with
the same 20 source findings and exit 1, proving the failure is not only a
timeout. `go fmt ./...` introduced no worktree changes, and `git diff --check`
passed.

Result: **FAIL**. Findings were recorded and not repaired, as required by the
verification-only scope.

## Container verification

`docker info` exited 0 and reported Docker client/server 29.7.2 on Linux/AMD64. The host has Compose plugin v5.5.0 but lacks the separate legacy executable, so a temporary `/tmp/docker-compose` symlink to that plugin was placed on `PATH`. This allowed the unchanged Makefile to invoke its required command.

From `deployments/`, `IMG_REPO=peirates-local IMG_REPO_DEV=peirates-dev-local make build dev` exited 2 in the production build. Its Go 1.17.3 builder cannot parse the repository Go 1.25.0 directive:

```text
go: errors parsing go.mod:
/usr/local/go/src/peirates/go.mod:3: invalid go version '1.25.0': must match format 1.23
make: *** [Makefile:9: build] Error 1
```

Because Make stopped before `dev`, `IMG_REPO_DEV=peirates-dev-local make dev` was run independently. It built intermediate `peirates-dev:latest`, then exited 2 because the Makefile image-ID extraction was empty and the required local tag was not created:

```text
Image peirates-dev Built
docker tag  peirates-dev-local:latest
docker: 'docker tag' requires 2 arguments
make: *** [Makefile:22: dev] Error 1
```

The intermediate image was ID `sha256:3766ed638a283008116896139e08ee3e38f8b8bcdd6b731683684ec731c1dcce`, size 168,982,521 bytes (`docker image ls` displayed 671MB with shared content).

| Command | Exit | Result |
| --- | ---: | --- |
| `docker info` | 0 | Daemon accessible |
| combined production/development Make command | 2 | Production builder rejected `go 1.25.0`; Make did not reach `dev` |
| independent development Make command | 2 | Intermediate built; required retag failed |
| `docker image inspect peirates-local:latest peirates-dev-local:latest` | 1 | Both required tags absent |
| `docker run --rm peirates-local:latest -c -m pwd` | 125 | Required image absent; no banner or working-directory result |

No registry login, push, or publish command was run. Nothing was pushed or published.

## Kind integration and cleanup

Before the test, `kind get clusters` exited 0 with `No kind clusters found.` The exact isolated command was run:

```sh
KIND_CLUSTER_NAME=peirates-refactor-verification make kind-test
```

It exited 0. Kind created the isolated cluster, waited for readiness, and created its temporary namespace, service account, and view binding.

```text
=== RUN   TestKindListsNamespaces
--- PASS: TestKindListsNamespaces (0.12s)
PASS
ok   github.com/inguardians/peirates/internal/app  0.195s
```

The cleanup trap deleted the cluster. The required post-test `kind get clusters` exited 0 with `No kind clusters found.`, independently proving cleanup; no manual deletion was necessary.

## Ending worktree

The ending `git status --short` matched the starting output exactly:

```text
 M .gitignore
 D attack_create_hostfs_pod.go
 D aws.go
 D aws_test.go
 D cloud_detection.go
 D cloud_detection_test.go
 M cmd/peirates/peirates.go
 D commandline.go
 D config.go
 D config_output_node_test.go
 D curl.go
 D cve-2024-21626.go
 D decode_jwt.go
 D decode_jwt_test.go
 D enumerate_dns.go
 D enumerate_simple_objects.go
 D enumerate_simple_objects_test.go
 D exec_in_pods.go
 D exec_via_kubelet_api.go
 D filesystem_manipulation.go
 D filesystem_manipulation_test.go
 D gcp.go
 D gcp_test.go
 D http_utils.go
 D inject-into-pod-alpha.go
 D json_structs.go
 D kind_integration_test.go
 D kubeapi.go
 D kubectl_interactive.go
 D kubectl_wrappers.go
 D list_secrets.go
 D menu.go
 D menu_cert_auth.go
 D menu_namespaces.go
 D menu_serviceaccounts.go
 D menu_tcp_portscan.go
 D menu_use_auth_cani.go
 D misc_utils.go
 D misc_utils_test.go
 D module_commands_test.go
 D module_dispatch.go
 D node_secrets.go
 D output_to_user.go
 D peirates.go
 D portscan.go
 D portscan_test.go
 D run_external_programs.go
 D run_external_programs_test.go
 D service_account_utils.go
 D service_account_utils_test.go
 D transport_test.go
?? .agents/
?? AGENTS.md
?? docs/architecture.md
?? docs/external-verification-results.md
?? docs/refactor-verification.md
?? go.sum
?? internal/
?? plan.txt
```

There were no unexpected source, dependency, script, Docker, deployment, or
test changes. Final `git diff --check` passed. No credentials or tokens were
captured, and no image, artifact, commit, or other content was pushed or published. No registry login or push target was invoked.

## Final checklist

| Check | Status |
| --- | --- |
| Lint/security | **FAIL** — 100 golint, 26 gosec, and 20 golangci findings |
| Production image | **FAIL** — Go 1.17.3 builder rejected the Go 1.25.0 module directive |
| Development image | **FAIL** — required `peirates-dev-local:latest` retag failed |
| Container smoke test | **FAIL** — production tag absent; no banner or `pwd` result |
| Kind integration test | **PASS** — isolated test passed |
| Kind cleanup verification | **PASS** — no Kind clusters remained |

This is not a fully successful handoff because lint/security and all container checks failed. Per the verification-only scope, failures were recorded and not repaired; production code, dependencies, scripts, Dockerfiles, deployment files, and test expectations were not changed.
