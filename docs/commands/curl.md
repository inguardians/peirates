# Make an HTTP request

## Menu entry

- **Menu item:** 91
- **Canonical command:** `curl`
- **Maturity:** Supported, with a limited curl-like argument set

## Purpose

Make an HTTP request from Peirates' network location, including requests to cluster-local, node-local, or cloud metadata endpoints that the operator is authorized to access. The wizard supports GET and POST; direct mode accepts an arbitrary method with `-X`.

## Prerequisites and authorization

The target must be reachable from the Peirates process. Requests can disclose credentials or change remote services; obtain authorization for the target and method.

## Usage

Bare `curl` opens a wizard for URL, TLS behavior, method, headers, and parameters. A one-line form supports `-X`, `-k`, `-H`, and `-d`:

```text
curl -H Accept:application/json https://service.example/status
curl -X POST -d key=value http://service.example/action
curl -X DELETE https://service.example/resource/123
```

```sh
peirates -m 'curl -k https://service.example/status'
```

## What it does

The wizard constructs a GET or POST and can place parameters in the query string or request body. The direct form defaults to GET, but `-X` accepts any method string supported by Go's HTTP client, such as PUT, PATCH, or DELETE. Direct mode places `-d key=value` parameters in the body only for POST and in the URL for every other method, and optionally disables TLS verification with `-k`.

## Expected output

The response body is printed and can be appended to the configured output file.

## Side effects and cleanup

HTTP requests may trigger remote state changes. Direct mode is not limited to GET and POST: methods such as PUT, PATCH, and DELETE can modify or remove remote resources. Confirm the target and method before sending the request. `-k` disables server-certificate verification and should be limited to controlled environments. Peirates does not provide remote cleanup.

## Failure modes

The URL must include `http://` or `https://`. Only GET and POST are supported by the wizard; direct mode passes the uppercased `-X` value to Go's HTTP request constructor and rejects methods that are not valid HTTP method tokens. The wizard lowercases the complete URL, which can alter case-sensitive paths and parameter values. Missing flag values, malformed headers, `-d` values without `=`, TLS errors, and network failures cause the request to fail. Direct arguments are split on whitespace, so values containing spaces are limited.

## Implementation and tests

See [`curl.go`](../../internal/app/curl.go), [`http_utils.go`](../../internal/app/http_utils.go), and the direct dispatcher in [`peirates.go`](../../internal/app/peirates.go). Request construction and transport are tested in [`transport_test.go`](../../internal/app/transport_test.go), and dispatch in [`module_commands_test.go`](../../internal/app/module_commands_test.go).
