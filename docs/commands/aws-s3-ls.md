# `aws-s3-ls`

## Menu entry

- Number: `17`
- Canonical command: `aws-s3-ls`
- Accepted aliases: `17`, `aws-ls-s3`, `ls-s3`, `s3-ls`
- Menu display: `aws-s3-ls` (matches the canonical command)
- Maturity: Supported; metadata behavior is unit-tested, but the S3 listing path lacks a focused API test.

## Purpose

List the names of S3 buckets visible to the current AWS credentials. This is a read-only enumeration command, but **Peirates prints the full AWS secret access key and session token while creating the S3 client**.

## Prerequisites and authorization

- AWS credentials in an assumed interactive role, the current Peirates session, environment variables, or AWS IMDS.
- Access to AWS placement metadata at `169.254.169.254`; Peirates derives the S3 region from the instance availability zone even when credentials came from another source.
- AWS authorization to list buckets for the current account or principal.
- Explicit authorization to enumerate the target account's S3 resources.

At startup, Peirates loads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` when present. If no session credential exists, this command tries IMDSv1 and then IMDSv2.

## Usage

In the interactive classic menu, enter the number, canonical command, or any accepted alias:

```text
17
aws-s3-ls
aws-ls-s3
ls-s3
s3-ls
```

There is no prompt, so one-shot use is appropriate:

```sh
peirates -m aws-s3-ls
```

## What it does

1. Prefers an assumed-role credential, then current session credentials.
2. If neither exists, retrieves credentials with IMDSv1 and falls back to IMDSv2 on error.
3. Reads the AWS availability zone from metadata and removes its final character to derive a region.
4. Creates an AWS SDK S3 client with static credentials and TLS certificate verification disabled.
5. Calls `ListBuckets` and prints each returned bucket name on its own line.

## Expected output

Before the bucket names, Peirates prints messages about credential retrieval and session creation, including:

```text
aws_access_key_id = <access-key-id>
aws_secret_access_key = <secret-access-key>
aws_session_token = <session-token>
Using region <region>
```

Each accessible bucket name then appears on a separate line. No summary is printed for an empty result.

## Side effects and cleanup

The command performs metadata and S3 read operations only. It does not modify buckets or objects and does not write a credential file. Because complete AWS credentials are written to standard output, protect or remove terminal logs and recordings after the assessment.

## Failure modes

- No session credentials are present and IMDSv1/IMDSv2 cannot provide them.
- Placement metadata is unavailable or the availability-zone value is invalid; there is no region flag or normal AWS SDK region fallback in this path.
- AWS rejects `ListBuckets` because of credentials, policy, endpoint, clock, or network errors.
- The S3 client disables TLS verification, which weakens transport authentication and may be prohibited by the assessment environment.
- Region discovery can return a nil S3 client, and `ListAWSBuckets` does not check for nil before use; this can panic instead of returning a clean error.
- The metadata and custom S3 HTTP clients have no overall request timeout, so some network failures can block longer than expected.

Metadata and region behavior have focused tests. S3 client creation and `ListBuckets` currently do not have isolated AWS API tests.

## Implementation and tests

- Handler registration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- Credential selection and S3 listing: [`internal/app/aws.go`](../../internal/app/aws.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Classic menu and completion: [`internal/app/menu.go`](../../internal/app/menu.go)
- AWS metadata and region tests: [`internal/app/aws_test.go`](../../internal/app/aws_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
