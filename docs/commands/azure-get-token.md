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
2. Identity selector: a discovered candidate's number, `default`, `client-id`, `object-id`, or `msi-res-id`.
3. The identifier, if selecting an explicit identity.

After the resource prompt, Peirates discovers identity candidates and prints their client IDs and sources. A single candidate is the default choice. Multiple candidates require an explicit choice; blank input cancels the request with an error. If there are no candidates, the identity prompt defaults to `default`, letting IMDS choose. You can also enter `default` explicitly to use IMDS selection even when candidates exist. Environments with multiple user-assigned identities can reject that choice.

EOF or an input error cancels without requesting a token. An entered line containing a Ctrl-C or Escape character also cancels; terminal Ctrl-C handling may instead terminate the process.

Options skip prompts, even in the interactive menu. Explicit `--client-id`, `--object-id`, or `--msi-res-id` bypass discovery; the three selector options are mutually exclusive. Without a selector, one discovered candidate is selected automatically. Multiple candidates are listed and require rerunning with an explicit selector. With no candidates, IMDS default selection is attempted. `--no-discovery` skips discovery and preserves IMDS default selection when no selector is supplied. `--help` prints usage without file or network access.

```sh
peirates -c -m azure-get-token
peirates -c -m 'azure-get-token --list-identities'
peirates -c -m 'azure-get-token --no-discovery'
peirates -c -m '36 --resource https://vault.azure.net --client-id <client-id>'
peirates -c -m 'get-azure-token --object-id <object-id>'
peirates -c -m 'azure-get-token --msi-res-id /subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity>'
```

`-m` always runs without prompts, including the bare command. Inline arguments support quotes and backslash escaping without shell execution or variable expansion by Peirates. Explicitly empty values, extra positional arguments, unknown options, malformed quotes, and conflicting selectors are errors.

## Identity discovery

Discovery combines these two sources:

1. `/etc/kubernetes/azure.json`: when `useManagedIdentityExtension` is `true`, the `userAssignedIdentityID` field supplies a candidate client ID. The file must be readable by the current process; Peirates does not elevate privileges. Other configuration fields, including service principal credentials, are not displayed or retained.
2. IMDS instance metadata at `http://169.254.169.254/metadata/instance?api-version=2021-02-01`: values of `compute.tagsList` entries named `aks-managed-kubeletIdentityClientID` supply candidate client IDs. Other tags are ignored.

Candidates must have GUID syntax. IDs are normalized to lowercase, deduplicated across sources, and sorted. Each candidate shows every source that supplied it. These are configuration hints, not a complete inventory of attached identities; an IMDS token request confirms whether a candidate is usable.

`--list-identities` performs discovery and prints the candidates without prompting, requesting a token, or changing retained tokens. It cannot be combined with an identity selector or `--no-discovery`.

```text
[+] Azure identity candidates (IMDS availability is confirmed when requesting a token):
  1. aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
     Source: /etc/kubernetes/azure.json (userAssignedIdentityID); IMDS tag aks-managed-kubeletIdentityClientID
```

A missing configuration file is skipped. Unreadable, malformed, oversized, or invalid source data produces a diagnostic while findings from the other source remain available. Discovery does not try every candidate or retry a failed token request using a different identity. No discoveries does not establish that the node has no managed identity.

## What it does

When discovery is needed, the command reads the local configuration with a 1 MiB limit and makes one GET to IMDS instance metadata. After selection, it makes one token GET to `http://169.254.169.254/metadata/identity/oauth2/token`, with `Metadata: true`, API version `2018-02-01`, a URL-encoded `resource`, and the selected `client_id`, `object_id`, or `msi_res_id`. Both metadata requests use a dedicated direct HTTP transport that bypasses environment proxies, rejects redirects, and imposes a five-second deadline and 1 MiB response limit per request. Neither request is retried. Listing or an ambiguous candidate selection stops before the token request.

It accepts a nonempty bearer token with a future `expires_on` Unix timestamp (JSON number or numeric string). A nonempty returned resource must match the requested resource. On success it displays:

```text
[+] Azure managed identity token
Resource: https://management.azure.com/
Identity selection: default
Expires (UTC): 2026-10-12T13:00:00Z
Decoded identity claims (signature not verified):
  Managed identity: /subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity>
  Client ID:        <client-id>
  Principal ID:     <principal-id>
  Tenant ID:        <tenant-id>
  Source resource:  /subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.Compute/virtualMachineScaleSets/<vmss>/virtualMachines/<instance>
Bearer token: <bearer-token>
```

The identity summary decodes these JWT payload claims locally when available:

| Display field | Claim | Meaning |
| --- | --- | --- |
| Managed identity | `xms_mirid` | User-assigned identity resource ID, or the owning resource ID for a system-assigned identity. |
| Client ID | `appid` / `azp` | Client application ID; v1 tokens use `appid`, v2 tokens use `azp`. |
| Principal ID | `oid` | Service principal object ID. |
| Tenant ID | `tid` | Microsoft Entra tenant containing the principal. |
| Source resource | `xms_az_rid` | Resource using the identity, such as the VM or AKS node, when present. |

These are unverified claims for inspection; the decoder does not verify the token signature or use claims to change session identity keys. It shows only available nonempty string fields and escapes terminal control characters. Missing fields are omitted, and the presence or absence of `xms_az_rid` is not used to classify the identity. Opaque or malformed JWTs produce an unavailable-summary message, and JWTs with no supported identity fields say so. In each case, successful token acquisition, printing, and retention continue. Decoding requires no additional network requests.

Tokens remain in the current Peirates session, separate from Kubernetes authentication. Each identity/resource combination retains its most recently acquired token. Identity keys use the returned `client_id` when available, otherwise the original selector or a default marker. Resource keys use the exact requested URI. A later successful acquisition replaces its matching entry; failures preserve all entries. Every invocation requests a token again; there is no automatic refresh.

The session banner shows identity, resource, UTC expiration, and whether each entry is expired, without printing the token again. The collection is lost when Peirates exits. The command does not write tokens to disk, but terminal capture can retain the printed credentials.

## Failure modes and side effects

Network errors, inaccessible IMDS, unavailable or ambiguous identities, unsupported resources, and non-200 responses produce a command error. HTTP failures include the status and structured Azure `error`/`error_description` fields when available. Raw response bodies are not printed. Malformed IMDS token responses, missing bearer tokens, expired tokens, redirects, oversized bodies, and timeouts are rejected. JWT decoding failures affect only the identity summary.

This metadata operation does not create or modify Azure or Kubernetes resources and needs no resource cleanup. Existing global `-m` exit behavior is preserved; inspect command output for acquisition success or failure.

## Validation

Local files and HTTP fixtures cover discovery from both sources, deduplication, conflicting candidates, partial failures, unrelated-field redaction, listing without token acquisition, explicit overrides, request encoding and headers, every selector, bounded transport, response validation, errors, prompt cancellation, retention, aliases, and `-m` execution. Identity-summary fixtures cover user-assigned and system-assigned identities, v1/v2 client IDs, missing or incorrectly typed claims, opaque or malformed tokens, and escaped terminal control characters. No Azure access is required for automated tests.

For optional live verification on an authorized Azure VM or an AKS workload that can access IMDS, run `azure-get-token --list-identities`, confirm the displayed sources, then select an assigned identity for an allowed resource. Compare with `--no-discovery` if testing IMDS default selection. Confirm the returned token's audience and expiration locally, repeat the request to verify replacement, and confirm the session banner omits the token.

## Implementation and references

- Provider client and fixtures: [`internal/cloud/azure`](../../internal/cloud/azure)
- Session orchestration and tests: [`internal/app/azure.go`](../../internal/app/azure.go), [`internal/app/azure_test.go`](../../internal/app/azure_test.go)
- [Microsoft IMDS managed identity token protocol](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- [Microsoft access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
- [Microsoft access token formats and inspection](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Microsoft IMDS proxy guidance](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#proxies)
- [AKS node configuration source](https://github.com/Azure/AgentBaker/blob/master/parts/linux/cloud-init/artifacts/cse_config.sh)
- [Microsoft IMDS instance metadata and tags](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#instance-metadata)
- [Observed AKS kubelet identity tag](https://www.danielstechblog.io/restrict-access-to-the-imds-endpoint-on-azure-kubernetes-service-with-cilium/)
