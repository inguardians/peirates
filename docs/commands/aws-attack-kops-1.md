# `aws-attack-kops-1`

## Menu entry

- Number: `16`
- Canonical command: `aws-attack-kops-1`
- Accepted aliases: `16`, `attack-aws-kops-1`
- Menu display: `attack-kops-aws-1`
- Maturity: Experimental and lightly tested; metadata helpers have tests, but the S3 extraction flow does not.

The displayed and tab-completed name `attack-kops-aws-1` is **not** accepted. The accepted historical alias instead orders the words as `attack-aws-kops-1`.

## Purpose

Search S3 buckets visible to the current AWS credentials for kOps state objects under `/secrets/`, decode Kubernetes service-account tokens, and optionally add them to Peirates' in-memory store. **This command extracts and prints credentials.** Run it only against AWS accounts, buckets, and Kubernetes environments explicitly included in the assessment.

## Prerequisites and authorization

- AWS credentials from an assumed role, the current interactive Peirates session, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, or IMDSv1.
- Access to AWS IMDS placement metadata even when credentials were supplied another way; the S3 client derives its region from the instance availability zone.
- S3 authorization sufficient to list buckets, list objects in each relevant bucket, and read matching objects.
- kOps state stored in the expected S3 JSON object format with a base64 `Data` field.
- Authorization to enumerate those buckets and recover and use the Kubernetes credentials they contain.

## Usage

In the interactive menu, enter `16`, `aws-attack-kops-1`, or `attack-aws-kops-1`, then choose:

```text
1  Store all tokens found in Peirates data store
2  Retrieve and print all tokens
```

The choice is always read from standard input. For deterministic `-m` use, pipe it:

```sh
printf '2\n' | peirates -m aws-attack-kops-1
```

Without input, the command reports an input error and returns without scanning. Choice `1` is useful in the interactive session, but not in a one-shot `-m` process because the in-memory store is discarded at exit.

## What it does

1. Selects credentials in this order: assumed role, current AWS session credentials, then IMDSv1 credentials.
2. Lists the buckets visible to those credentials.
3. Creates an S3 client after deriving the region from AWS placement metadata.
4. Lists the first page of objects in every returned bucket.
5. For keys containing `/secrets/`, downloads the object, unmarshals its `Data` field, base64-decodes it, and prints the Kubernetes token.
6. If choice `1` was selected, adds the token to the current process as `AWS-acquired: <object-key>`.

Both S3 client creation and the search path print AWS credential values. The S3 HTTP client disables TLS certificate verification because the runtime may lack a CA store.

## Expected output

Output identifies the credential-selection and S3-session steps, prints the AWS access key, secret key, and session token, names each bucket being listed, and prints each matching object's encoded and decoded Kubernetes token. Stored tokens additionally produce a `Storing token as:` message.

## Side effects and cleanup

AWS operations are reads; the command does not change buckets, objects, IAM roles, or Kubernetes resources. Choice `1` changes only Peirates' in-memory service-account list. Treat terminal output as highly sensitive and rotate or revoke recovered credentials when the authorized exercise calls for it.

## Failure modes

- No usable AWS credentials are available. This attack path only tries IMDSv1 when it must obtain credentials itself; it does not fall back to IMDSv2.
- Placement metadata is unavailable or returns an invalid availability zone, even if valid AWS credentials were supplied through the environment.
- Bucket-list, object-list, or object-read access is denied.
- The S3 object is not JSON with the expected `Data` field, or the value is not valid base64.
- Only the first `ListObjectsV2` page is inspected; pagination is not implemented.
- A failure listing one bucket stops the entire scan.
- Region discovery can return a nil S3 client, and callers do not guard it before use; some region failures can therefore panic.
- The metadata and custom S3 HTTP clients have no overall request timeout, so some network failures can block longer than expected.

The AWS metadata helpers and command reachability are tested, but the S3 bucket-search and token-extraction flow has no focused automated test and should be considered lightly tested.

## Implementation and tests

- Handler and in-memory-store integration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- Credential selection, S3 enumeration, and token extraction: [`internal/app/aws.go`](../../internal/app/aws.go)
- S3 object shape: [`internal/app/json_structs.go`](../../internal/app/json_structs.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Displayed menu name and completion names: [`internal/app/menu.go`](../../internal/app/menu.go)
- AWS metadata and region tests: [`internal/app/aws_test.go`](../../internal/app/aws_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
