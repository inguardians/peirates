# `aws-s3-ls-objects`

## Menu entry

- Number: `18`
- Canonical command: `aws-s3-ls-objects`
- Accepted aliases: `18`, `aws-s3-list-objects`, `aws-s3-list-bucket`
- Menu display: `aws-s3-ls-objects` (matches the canonical command)
- Maturity: Supported but lightly tested; prompt reachability has smoke coverage, while the S3 success path does not.

## Purpose

List object metadata from a named S3 bucket using the current AWS credentials. The object contents are not downloaded. This is a read-only enumeration operation, but **Peirates prints the full AWS credentials used to create the S3 client**.

## Prerequisites and authorization

- In interactive mode, AWS credentials previously entered into the session or an assumed role.
- In a fresh `-m` process, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and normally `AWS_SESSION_TOKEN` in the environment. Unlike `aws-s3-ls`, this handler does not fetch credentials from IMDS when the session has none.
- Access to AWS placement metadata at `169.254.169.254`, because the S3 client always derives its region from the instance availability zone.
- AWS authorization to list objects in the named bucket and explicit authorization to enumerate it.

Due to the current `aws-get-token` handler's reversed success check, a successful item 12 run does not populate the interactive session. Manually entered or environment credentials are the reliable choices for this command.

## Usage

In the interactive menu, enter `18`, `aws-s3-ls-objects`, `aws-s3-list-objects`, or `aws-s3-list-bucket`, then enter the bucket name at the prompt.

The bucket name cannot be appended to the `-m` value; the handler always reads it from standard input. For one-shot use:

```sh
printf '%s\n' '<bucket-name>' | peirates -m aws-s3-ls-objects
```

Without standard input, the module prints `Error reading input` and returns. This makes it scriptable through a pipe, but not fully argument-driven.

## What it does

1. Prompts for a bucket name.
2. Uses an assumed role if the interactive session has one; otherwise uses the session's ordinary AWS credentials.
3. Gets the availability zone from IMDS and derives the region.
4. Creates an AWS SDK S3 client with static credentials and TLS certificate verification disabled.
5. Calls `ListObjectsV2` once for the named bucket.
6. Prints each returned object's key, last-modified time, size, and storage class.

The implementation does not request subsequent pages, so buckets with more than one response page are only partially listed.

## Expected output

Peirates first prints the credentials and derived region, then emits a block for each object:

```text
Name:            <object-key>
 | Last modified: <timestamp>
 || Size:          <bytes>
 ||| Storage class: <class>
```

An empty bucket produces no object blocks.

## Side effects and cleanup

The command reads metadata and S3 object listings only. It does not download, create, modify, or delete objects. Full AWS credentials and potentially sensitive object names are written to standard output; protect or remove captured output after use.

## Failure modes

- The bucket name is absent from standard input.
- No ordinary or assumed session credentials are available; this handler does not acquire them from IMDS.
- Placement metadata is unreachable or returns an invalid availability zone, even when valid environment credentials exist.
- The bucket does not exist, is in an incompatible endpoint context, or the principal lacks object-list permission.
- `ListBucketObjects` logs AWS API failures but currently returns nil, so the menu wrapper may not report its own `Error listing bucket objects` message.
- Region discovery can return a nil S3 client, and the caller does not guard it before use; some failures can panic.
- Only the first `ListObjectsV2` response page is printed.
- TLS certificate verification is disabled for S3 requests.
- The metadata and custom S3 HTTP clients have no overall request timeout, so some network failures can block longer than expected.

The command has `-m` no-hang coverage, but the prompt-success and S3 API paths do not have focused automated tests.

## Implementation and tests

- Handler registration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- Prompt, S3 session, and object listing: [`internal/app/aws.go`](../../internal/app/aws.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Classic menu and completion: [`internal/app/menu.go`](../../internal/app/menu.go)
- AWS metadata and region tests: [`internal/app/aws_test.go`](../../internal/app/aws_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
