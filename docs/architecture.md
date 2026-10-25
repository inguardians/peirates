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
- `internal/cloud` and its `aws`, `gcp`, and `azure` children contain provider detection
  and metadata clients.
- `internal/modules` contains the command registry and local filesystem, DNS,
  port-scanning, and shell capabilities.
- `internal/token` contains JWT decoding and display helpers.

Packages below `internal/` are implementation details, not a supported public
API. Capability packages must not import `internal/app`; dependencies point
toward `internal/model`, and app supplies mutable state or narrow callbacks.

Within `internal/app`, `module_dispatch.go` owns shared command routing, including
cloud token commands with inline options. `command_args.go` parses quoted and
escaped arguments for that dispatcher and nodes-proxy commands without shell
expansion. Provider-specific files such as `azure.go` and `aws_node_token.go`
own option validation and provider operations; shared routing belongs in the
neutral dispatcher.

`aws-get-eks-node-token` uses the AWS provider's bounded IMDS, discovery, and signing
client, with app orchestration retaining typed `model.AWSNodeToken` entries.
These credentials are separate from service-account JWTs. Kubernetes helpers
resolve in-cluster trust and perform isolated SelfSubjectReview verification.
Explicit activation records expiry on `ServerInfo`; API and kubectl paths
reject expired generated credentials, and identity switches clear that state.
Active node-token kubectl calls use a private temporary kubeconfig, removed
after the call, to avoid ambient credentials and bearer tokens in process
arguments. Module-mode node-token invocation bypasses legacy startup credential
discovery so its metadata requests use only the dedicated bounded provider.

Build and deployment paths remain unchanged. Use `go build ./cmd/peirates`,
`make build`, and `make test` from the repository root. The Kind test remains
opt-in through `make kind-test`.
