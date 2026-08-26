# `gcp-attack-kops-1`

## Menu entry

- Number: `15`
- Canonical command: `gcp-attack-kops-1`
- Accepted aliases: `15`, `attack-kops-gcs-1`
- Menu display: `gcp-attack-kops-gcs-1`
- Maturity: Experimental and lightly tested; the flow relies on brittle line-oriented response parsing.

The displayed name is inconsistent with dispatch: `gcp-attack-kops-gcs-1` is **not** accepted. Use the canonical command or one of the accepted aliases above. Tab completion offers `gcp-attack-kops-1` and `attack-kops-gcs-1`.

## Purpose

Search GCS buckets visible to the workload's default GCP service account for kOps state objects under `/secrets/`, decode Kubernetes service-account tokens, and optionally add them to Peirates' in-memory store. **This is a credential-extraction operation and prints both a GCP bearer token and recovered Kubernetes tokens.** Use it only within an explicitly authorized assessment scope.

## Prerequisites and authorization

- Network access to the GCP metadata server and `www.googleapis.com`.
- A default GCP service account available from metadata.
- Cloud Storage authorization sufficient to list buckets for the metadata-reported project, list objects in accessible buckets, and read matching objects.
- kOps state stored in the expected GCS object and JSON/base64 format.
- Authorization to enumerate those buckets and recover and use the Kubernetes credentials they contain.

## Usage

In the interactive menu, enter `15`, `gcp-attack-kops-1`, or `attack-kops-gcs-1`, then choose:

```text
1  Store all tokens found in Peirates data store
2  Retrieve and print all tokens
```

The handler always reads that choice from standard input, so it is not a fully argument-driven one-shot module. Pipe a choice for deterministic `-m` use:

```sh
printf '2\n' | peirates -m gcp-attack-kops-1
```

Running `peirates -m gcp-attack-kops-1` with closed standard input logs a scan error and then continues in print-only mode. Choice `1` has little value with `-m`, because the in-memory store disappears when the one-shot process exits.

## What it does

1. Requests a bearer token for the `default` service account and prints it.
2. Reads the numeric project ID from metadata.
3. Calls the Cloud Storage JSON API to list project buckets.
4. Extracts bucket `selfLink` values from the response using line-oriented string parsing.
5. Lists objects in each returned bucket and selects object links containing URL-encoded `%2Fsecrets%2F`.
6. Downloads each matching object with `?alt=media`, extracts base64 text, decodes it, and prints the Kubernetes token.
7. If choice `1` was selected, adds each decoded token to the current Peirates process as `GCS-acquired: <name>`.

The implementation does not follow Cloud Storage pagination tokens, so it may not inspect every bucket or object in a large project.

## Expected output

Output includes the selected-mode prompt, the raw default GCP bearer token, the numeric project ID, each bucket being checked, matching service-account names, and raw decoded Kubernetes tokens. Stored tokens additionally produce a `Storing token as:` message.

## Side effects and cleanup

The cloud operations are reads; the command does not modify GCS objects or Kubernetes resources. Choice `1` changes only Peirates' in-memory service-account list for the current interactive process. All printed bearer and Kubernetes tokens are sensitive; remove or protect terminal recordings and revoke or rotate recovered credentials when the authorized exercise requires it.

## Failure modes

- Metadata, DNS, or Cloud Storage API access is unavailable.
- The default service account lacks bucket-list, object-list, or object-read access.
- The project ID, bucket list, object list, or object body is blank or returned as an error.
- Responses are valid JSON but not formatted with the expected one-`selfLink`-per-line layout; the parser is not a general JSON parser and can miss data or panic on malformed matching lines.
- Matching objects do not contain the expected quoted, base64-encoded token representation.
- A failed object read skips the remainder of that bucket; some other errors stop the entire scan.
- Pagination is not implemented.
- The generic HTTP helper has no request timeout, so metadata or Cloud Storage calls can block longer than expected.

The GCP token helper and `-m` reachability are tested, but the bucket-search and token-extraction flow has no focused automated test and should be considered lightly tested.

## Implementation and tests

- Handler and in-memory-store integration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- GCS enumeration and token extraction: [`internal/app/gcp.go`](../../internal/app/gcp.go)
- HTTP helper: [`internal/app/http_utils.go`](../../internal/app/http_utils.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Displayed menu name and completion names: [`internal/app/menu.go`](../../internal/app/menu.go)
- GCP token helper tests: [`internal/app/gcp_test.go`](../../internal/app/gcp_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
