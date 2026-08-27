# Developer Architecture

Peirates keeps its supported executable at `cmd/peirates`. The command is a
thin process-mode router into `internal/app`; it preserves normal invocation,
`peirates --kubectl ...`, and invocation through an executable named
`kubectl`.

`internal/app` owns construction, mutable `Session` state, option parsing,
canonical command aliases, and module registry composition. Lower-level code
is grouped by responsibility:

- `internal/model` contains shared Kubernetes and authentication value types.
- `internal/ui` owns stable menu, banner, completion, and output behavior.
- `internal/kube` contains transport, kubectl, credential value helpers,
  enumeration, and pod execution boundaries.
- `internal/cloud` and its `aws` and `gcp` children contain provider detection
  and metadata clients.
- `internal/modules` contains the command registry and local filesystem, DNS,
  port-scanning, and shell capabilities.
- `internal/token` contains JWT decoding and display helpers.

Packages below `internal/` are implementation details, not a supported public
API. Capability packages must not import `internal/app`; dependencies point
toward `internal/model`, and app supplies mutable state or narrow callbacks.

Build and deployment paths remain unchanged. Use `go build ./cmd/peirates`,
`make build`, and `make test` from the repository root. The Kind test remains
opt-in through `make kind-test`.
