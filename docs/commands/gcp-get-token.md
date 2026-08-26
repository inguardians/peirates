# `gcp-get-token`

## Menu entry

- Number: `13`
- Canonical command: `gcp-get-token`
- Accepted aliases: `13`, `get-gcp-token`
- Menu display: `gcp-get-token` (matches the canonical command)
- Maturity: Supported; token parsing is unit-tested, while account enumeration has smoke coverage only.

## Purpose

Enumerate service accounts exposed by the GCP Compute Metadata Server and print an OAuth bearer token for each account. **The printed bearer tokens are sensitive credentials.** Run this only in a GCP workload you are authorized to assess.

## Prerequisites and authorization

- Network and DNS access to `metadata.google.internal`.
- A GCP Compute environment with one or more service accounts exposed to the workload through the metadata server.
- Authorization to retrieve and use those service-account tokens.

The command sends the required `Metadata-Flavor: Google` header. It does not require Kubernetes API access.

## Usage

In the interactive classic menu, enter:

```text
13
gcp-get-token
get-gcp-token
```

The command does not prompt for input, so it is suitable for one-shot use:

```sh
peirates -m gcp-get-token
```

## What it does

1. Gets the list at `/computeMetadata/v1/instance/service-accounts/`.
2. Removes the trailing slash from each nonblank account name.
3. Gets `/instance/service-accounts/<account>/token` for each account.
4. Accepts a successful JSON response whose `token_type` is `Bearer`, removes trailing periods from the access token, and prints the token.

The command does not add the discovered GCP tokens to Peirates' service-account store; the source contains a TODO for that behavior.

## Expected output

For each account, Peirates prints a heading followed by the raw token:

```text
[+] GCP Credentials for account <account>

<bearer-token>
```

There is no summary and no expiration value in the output.

## Side effects and cleanup

This is a read-only metadata operation. It writes raw bearer tokens to standard output but does not persist them to disk or change cloud resources. Protect or remove captured terminal output when the assessment is complete.

## Failure modes

- The metadata hostname cannot be resolved or reached.
- The initial account-list response is empty or begins with `ERROR:`; the command returns without a detailed command-specific error.
- A token endpoint returns a non-200 status, an empty/error body, malformed JSON, or a token type other than `Bearer`.
- Individual account-token failures are skipped, so output may contain only a subset of the listed accounts.
- The helper's calculated expiration uses the numeric `expires_in` value as a Go duration without converting seconds; the command does not display or use that value, but callers should not rely on it.
- The HTTP helper has no request timeout, so an unresponsive endpoint can block longer than expected.

The token parser has focused tests; the service-account enumeration loop currently has only `-m` smoke coverage.

## Implementation and tests

- Handler registration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- Account enumeration and token parsing: [`internal/app/gcp.go`](../../internal/app/gcp.go)
- HTTP helper: [`internal/app/http_utils.go`](../../internal/app/http_utils.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Classic menu text: [`internal/app/menu.go`](../../internal/app/menu.go)
- Token response tests: [`internal/app/gcp_test.go`](../../internal/app/gcp_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
