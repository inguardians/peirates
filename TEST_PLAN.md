# Test plan

## Approach

Tests use only the Go standard library.  External process execution, terminal
input, Kubernetes endpoints, cloud metadata services, DNS, and the local
filesystem are isolated with temporary directories, `httptest` servers, and
test doubles introduced only where a direct dependency prevents deterministic
coverage.  Interactive entry points are exercised with their non-interactive
branches; their command construction and delegated calls are tested separately.

## Function inventory and suite ownership

| Source area | Functions covered | Test focus | Owner |
| --- | --- | --- | --- |
| `decode_jwt.go`, `service_account_utils.go`, `misc_utils.go`, `filesystem_manipulation.go`, `portscan.go`, `cloud_detection.go` | JWT/base64 parsing and formatting; account de-duplication and assignment; line/random helpers; directory helpers; CIDR and scan worker; cloud/container detection | valid, malformed, duplicate, empty, and error paths | Agent: helpers |
| `http_utils.go`, `kubeapi.go`, `kubectl_wrappers.go` | request construction/execution, curl argument parsing, IP discovery, Kubernetes request building, kubectl argument/config/auth/account-fallback handling | `httptest` protocol cases, query/body/header variants, TLS/error cases, fake kubectl executable | Agent: transport |
| `aws.go`, `gcp.go` | environment credential loading, metadata/token parsing, region extraction, STS/S3 request handling, GCP metadata/Kops parsing | isolated environment, `httptest` metadata/API responses, malformed payloads, expiry/error branches | Agent: cloud |
| `config.go`, `commandline.go`, `output_to_user.go`, `run_external_programs.go`, `nsenter.go` | pod/kubelet configuration parsing, flag helpers, CLI option handling, output and executable error propagation, namespace validation | temp filesystem/proc fixtures, captured output, invalid inputs | Primary agent |
| `enumerate_simple_objects.go`, `enumerate_dns.go`, `node_secrets.go`, `list_secrets.go`, `exec_in_pods.go`, `exec_via_kubelet_api.go` | Kubernetes object decoding/listing/mount discovery, DNS enumeration, secret capture/listing, pod execution delegation | fake Kubernetes/DNS responses and captured command calls | Primary agent |
| `menu*.go`, `curl.go`, `kubectl_interactive.go`, `inject-into-pod-alpha.go`, `attack_create_hostfs_pod.go`, `cve-2024-21626.go`, `peirates.go`, `cmd/peirates/peirates.go` | completion trees, non-interactive command/menu branches, entrypoint delegation and error handling | completion assertions plus faked dependencies; no live cluster, shell, or exploit execution | Primary agent |

## Completion criteria

Every function listed above gets at least one deterministic success or
behavioral test.  Functions with parsing, validation, or external I/O get
failure-path coverage too.  The completed suite must pass `go test ./...` with
an isolated Go build cache; tests must not require a cluster, cloud account,
root access, or internet access.
