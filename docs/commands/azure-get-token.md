# `azure-get-token`

## Menu entry

- Number: `36`
- Canonical command: `azure-get-token`
- Accepted aliases: `36`, `get-azure-token`
- Maturity: Supported with local HTTP protocol, interaction, and one-shot CLI tests; live Azure verification is optional.

## Purpose and prerequisites

Request a managed identity bearer token from Azure IMDS for a chosen resource (audience). The VM or workload must have access to `169.254.169.254` and an available managed identity. No Kubernetes permissions are needed. Cloud detection does not gate this command, including when startup uses `-c`.

The token is a sensitive credential and is printed in full. Use this command only where you are authorized to retrieve the workload's identity. Azure IMDS identity access depends on the host and workload configuration; an AKS workload with blocked IMDS access cannot use this command as a substitute for Azure Workload Identity.

## Usage

Enter `36`, `azure-get-token`, or `get-azure-token` in the menu. A bare interactive command prompts for:

1. Resource URI, default `https://management.azure.com/`.
2. Identity selector: `default`, `client-id`, `object-id`, or `msi-res-id`.
3. The identifier, if selecting an explicit identity.

Blank default selections accept the defaults. EOF or an input error cancels without requesting a token. An entered line containing a Ctrl-C or Escape character also cancels; terminal Ctrl-C handling may instead terminate the process. IMDS chooses the default identity; environments with multiple user-assigned identities can require an explicit selector.

Options skip prompts, even in the interactive menu. The resource and identity default independently when omitted. The three selector options are mutually exclusive. `--help` prints usage without a request.

```sh
peirates -c -m azure-get-token
peirates -c -m '36 --resource https://vault.azure.net --client-id <client-id>'
peirates -c -m 'get-azure-token --object-id <object-id>'
peirates -c -m 'azure-get-token --msi-res-id /subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity>'
```

`-m` always runs without prompts, including the bare command. Inline arguments support quotes and backslash escaping without shell execution or variable expansion by Peirates. Explicitly empty values, extra positional arguments, unknown options, malformed quotes, and conflicting selectors are errors.

## What it does

The command makes one GET request to `http://169.254.169.254/metadata/identity/oauth2/token`, with `Metadata: true`, API version `2018-02-01`, a URL-encoded `resource`, and the selected `client_id`, `object_id`, or `msi_res_id`. A dedicated direct HTTP transport bypasses environment proxies, rejects redirects, and imposes a five-second overall deadline and 1 MiB response limit. It does not retry.

It accepts a nonempty bearer token with a future `expires_on` Unix timestamp (JSON number or numeric string). A nonempty returned resource must match the requested resource. On success it displays:

```text
[+] Azure managed identity token
Resource: https://management.azure.com/
Identity selection: default
Expires (UTC): 2026-10-12T13:00:00Z
Bearer token: <bearer-token>
```

Tokens remain in the current Peirates session, separate from Kubernetes authentication. Each identity/resource combination retains its most recently acquired token. Identity keys use the returned `client_id` when available, otherwise the original selector or a default marker. Resource keys use the exact requested URI. A later successful acquisition replaces its matching entry; failures preserve all entries. Every invocation requests a token again; there is no automatic refresh.

The session banner shows identity, resource, UTC expiration, and whether each entry is expired, without printing the token again. The collection is lost when Peirates exits. The command does not write tokens to disk, but terminal capture can retain the printed credentials.

## Failure modes and side effects

Network errors, inaccessible IMDS, unavailable or ambiguous identities, unsupported resources, and non-200 responses produce a command error. HTTP failures include the status and structured Azure `error`/`error_description` fields when available. Raw response bodies are not printed. Malformed tokens, expired tokens, redirects, oversized bodies, and timeouts are rejected.

This metadata operation does not create or modify Azure or Kubernetes resources and needs no resource cleanup. Existing global `-m` exit behavior is preserved; inspect command output for acquisition success or failure.

## Validation

Local HTTP fixtures cover request encoding and headers, every selector, bounded transport, response validation, errors, prompt cancellation, retention, aliases, and `-m` execution. No Azure access is required for automated tests.

For optional live verification on an authorized Azure VM or an AKS workload that can access IMDS, run the default command, then request an assigned identity by client ID for an allowed resource. Confirm the returned token's audience and expiration locally, repeat the request to verify replacement, and confirm the session banner omits the token.

## Implementation and references

- Provider client and fixtures: [`internal/cloud/azure`](../../internal/cloud/azure)
- Session orchestration and tests: [`internal/app/azure.go`](../../internal/app/azure.go), [`internal/app/azure_test.go`](../../internal/app/azure_test.go)
- [Microsoft IMDS managed identity token protocol](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- [Microsoft IMDS proxy guidance](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#proxies)
