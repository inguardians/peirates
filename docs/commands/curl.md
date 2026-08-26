# Make an HTTP request

## Menu entry

- **Menu item:** 91
- **Canonical command:** `curl`
- **Maturity:** Supported, with a limited curl-like argument set

## Purpose

Make a GET or POST request from Peirates' network location, including requests to cluster-local, node-local, or cloud metadata endpoints that the operator is authorized to access.

## Prerequisites and authorization

The target must be reachable from the Peirates process. Requests can disclose credentials or change remote services; obtain authorization for the target and method.

## Usage

Bare `curl` opens a wizard for URL, TLS behavior, method, headers, and parameters. A one-line form supports `-X`, `-k`, `-H`, and `-d`:

```text
curl -H Accept:application/json https://service.example/status
curl -X POST -d key=value http://service.example/action
```

```sh
peirates -m 'curl -k https://service.example/status'
```

## What it does

The wizard constructs a GET or POST and can place parameters in the query string or request body. The direct form defaults to GET, places `-d key=value` parameters in the body for POST and in the URL otherwise, and optionally disables TLS verification with `-k`.

## Expected output

The response body is printed and can be appended to the configured output file.

## Side effects and cleanup

HTTP requests may trigger remote state changes. `-k` disables server-certificate verification and should be limited to controlled environments. Peirates does not provide remote cleanup.

## Failure modes

The URL must include `http://` or `https://`. Only GET and POST are supported by the wizard. The wizard lowercases the complete URL, which can alter case-sensitive paths and parameter values. Missing flag values, malformed headers, `-d` values without `=`, TLS errors, and network failures cause the request to fail. Direct arguments are split on whitespace, so values containing spaces are limited.

## Implementation and tests

See [`curl.go`](../../internal/app/curl.go), [`http_utils.go`](../../internal/app/http_utils.go), and the direct dispatcher in [`peirates.go`](../../internal/app/peirates.go). Request construction and transport are tested in [`transport_test.go`](../../internal/app/transport_test.go), and dispatch in [`module_commands_test.go`](../../internal/app/module_commands_test.go).
