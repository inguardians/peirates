# Cloud-neutral command dispatch refactor

Status: Implemented after review. Shared routing and argument parsing now live
in neutral files; provider-specific behavior remains in its existing files.

## Purpose

Move shared command dispatch and argument parsing into files named for their
responsibility. Keep Azure-specific behavior in `azure.go` and AWS-specific
behavior in `aws_node_token.go`, preserving all existing CLI behavior.

## Structure before the refactor

- `internal/app/azure.go` defines `runModuleCommand`, although it dispatches both
  `azure-get-token` and `aws-get-eks-node-token` with inline options, then falls
  back to the general module registry.
- `internal/app/module_dispatch.go` already contains `canonicalModuleCommand`.
  It is the natural home for the shared dispatch function.
- `internal/app/nodes_proxy_exec.go` defines `parseNodesProxyCommand`, a generic
  quote-and-escape parser also used by the cloud command dispatcher.
- `internal/app/dispatch.go` owns aliases, and `module_registry.go` registers
  handlers for bare commands. `peirates.go` calls the dispatcher from the main
  loop and from the early AWS node-token module path.
- `azure_test.go` currently mixes shared dispatch checks with Azure-specific
  request and completion checks. AWS command-mode coverage lives in
  `aws_node_token_test.go`.

## Approved changes

### 1. Move shared dispatch into `module_dispatch.go`

Move `runModuleCommand` from `azure.go` into the existing
`internal/app/module_dispatch.go`, keeping its signature and dispatch logic.
Move its `modules` and `os` imports out of `azure.go` when they become unused.

The neutral dispatcher will continue calling `requestAzureToken` and
`requestAWSNodeToken`. Provider files will own their option validation, token
requests, identity handling, retention, and presentation. All remain in package
`app`; no new package, interface, or dependency is needed. Provider code may use
shared helpers in that package when appropriate.

### 2. Give the shared argument parser a neutral home

Move `parseNodesProxyCommand` into a new `internal/app/command_args.go` and rename
it to `parseCommandArgs`. Update the dispatcher and nodes-proxy caller to use
that name. Move its existing parser tests into `command_args_test.go` and rename
the test accordingly.

Preserve parsing exactly: whitespace splitting, single and double quotes,
escaped characters, empty quoted arguments, and errors for empty input,
unterminated quotes, and trailing escapes. This parser performs no shell
execution or expansion.

### 3. Put shared dispatch tests beside the dispatcher

Add `internal/app/module_dispatch_test.go` and move the shared dispatch assertions
out of `TestAzureDispatchAndCompletion`. Keep Azure-specific request, retention,
and completion assertions in `azure_test.go`. Retain the existing AWS subprocess
tests that exercise `Main` and detect unrelated startup requests.

Use focused cases covering both providers and ordinary registry dispatch:

- Canonical names and aliases: `azure-get-token`, `get-azure-token`, `36`,
  `aws-get-eks-node-token`, and `37`.
- Bare commands, inline options, quoted values, help, and invalid options.
- Malformed quoting is reported as a handled command without requesting a token.
- Similar command prefixes and unsupported inline arguments remain unrecognized.
- Registry fallback preserves both the handler result and the found flag,
  including `modules.Refresh` and unknown commands.

Reuse existing fixtures and operation stubs; tests must not contact real cloud
metadata endpoints or AWS/Azure services.

### 4. Document ownership

Add a short paragraph to `docs/architecture.md` identifying
`module_dispatch.go` as the shared routing boundary and `command_args.go` as the
shared argument parser. Future provider commands should add shared routing there
and keep provider-specific operations in their own files.

## Compatibility requirements

Preserve command names, aliases, menu numbers, completion, help and error text,
stream selection, interactive prompts, and noninteractive behavior. Preserve the
existing distinction between bare registry commands and supported inline-option
commands, including current whitespace handling.

Keep the AWS node-token early dispatch in `Main` before legacy startup probes.
Keep token acquisition, verification, activation, expiry checks, and session
retention unchanged. Preserve existing package boundaries, build outputs, and
deployment paths. Work against the current worktree and preserve unrelated
pending changes.

## Validation and acceptance

After implementation:

1. Run `go fmt ./...` with the repository's writable Go caches.
2. Run focused app tests for dispatch, argument parsing, Azure, AWS node tokens,
   and nodes-proxy command handling.
3. Run `make test-quiet` and `go build ./cmd/peirates`.
4. Smoke-test `-m 'azure-get-token --help'` and
   `-m 'aws-get-eks-node-token --help'`, using existing isolated subprocess
   fixtures where needed to avoid unrelated startup network requests.
5. Run `git diff --check` and inspect the diff for accidental behavioral changes.

Acceptance means `azure.go` contains no AWS routing or general registry dispatch,
shared parsing has a neutral name and file, and existing command behavior passes
regression checks. Live Kind or cloud testing is not required for this relocation;
if implementation changes Kubernetes API behavior, run the applicable Kind tests.

The dispatcher and parser bodies were compared against the pre-refactor commit
and are unchanged apart from the parser's name.
