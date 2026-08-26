# `gcp-attack-kube-env`

## Menu entry

- Number: `14`
- Canonical command: `gcp-attack-kube-env`
- Accepted aliases: `14`, `attack-kube-env-gcp`
- Menu display: `gcp-attack-kube-env` (matches the canonical command)
- Maturity: Supported but lightly tested; only command-level smoke coverage exists.

## Purpose

Read and print the GCP instance's `kube-env` metadata attribute. Installers and older cluster configurations may place Kubernetes bootstrap or credential material in this attribute, so **the output must be treated as sensitive even when no obvious token is present**.

## Prerequisites and authorization

- Network and DNS access to `metadata.google.internal`.
- A GCP instance whose metadata exposes the `instance/attributes/kube-env` key.
- Authorization to inspect that instance's metadata and any Kubernetes credentials or configuration it contains.

No bearer token or Kubernetes API permission is required for the metadata request itself.

## Usage

In the interactive classic menu, enter:

```text
14
gcp-attack-kube-env
attack-kube-env-gcp
```

The command does not prompt for input, so it can run non-interactively even though the classic menu does not mark it with `*`:

```sh
peirates -m gcp-attack-kube-env
```

## What it does

Peirates sends an HTTP GET to:

```text
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

It includes `Metadata-Flavor: Google`, requires HTTP 200 with a nonblank, non-`ERROR:` body, splits the body on newlines, and prints every line unchanged.

## Expected output

On success, the command prints the complete `kube-env` value line by line. The exact variables depend on how the cluster was created. On failure, it prints the metadata URL and may print the returned status code or request error.

## Side effects and cleanup

This command only reads metadata and writes it to standard output. It does not modify instance metadata, Kubernetes objects, or local files. Review terminal recordings and logs for exposed bootstrap tokens, certificates, keys, or configuration, and handle them as assessment artifacts.

## Failure modes

- The process is not on GCP or cannot resolve or reach the metadata hostname.
- The `kube-env` attribute is absent, blank, or access is denied.
- The metadata server returns a non-200 response or the HTTP request fails.
- The implementation uses a fixed production metadata URL rather than the injectable base used by the token helper, which limits focused testing and endpoint substitution.
- The HTTP helper has no request timeout, so an unresponsive endpoint can block longer than expected.

This is a simple read-only retrieval command, but it currently has only command-level smoke coverage rather than a focused success-path test.

## Implementation and tests

- Handler registration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- Metadata request and output: [`internal/app/gcp.go`](../../internal/app/gcp.go)
- HTTP helper: [`internal/app/http_utils.go`](../../internal/app/http_utils.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Classic menu text: [`internal/app/menu.go`](../../internal/app/menu.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
