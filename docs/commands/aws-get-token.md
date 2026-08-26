# `aws-get-token`

## Menu entry

- Number: `12`
- Canonical command: `aws-get-token`
- Accepted aliases: `12`, `get-aws-token`
- Menu display: `aws-get-token` (matches the canonical command)
- Maturity: Supported, with focused IMDS tests; interactive session storage is defective.

## Purpose

Retrieve temporary AWS IAM credentials from the EC2 Instance Metadata Service (IMDS) and print them. **The access key, secret access key, and session token are sensitive credentials.** Use this command only on an instance or workload you are authorized to assess.

## Prerequisites and authorization

- Network access to `http://169.254.169.254` from the Peirates process.
- An IAM role attached to the instance or workload, with credentials exposed through IMDS.
- Authorization to retrieve and use that workload's IAM credentials.

No Kubernetes API permission is required by this command itself.

## Usage

In the interactive classic menu, enter any accepted form:

```text
12
aws-get-token
get-aws-token
```

The command does not prompt for input, so it is suitable for one-shot use:

```sh
peirates -m aws-get-token
```

`-c` may be added to skip Peirates' separate startup cloud-detection pass; it does not disable this command's IMDS requests.

## What it does

1. Requests the attached role name and its credentials through IMDSv1.
2. If that initial IMDSv1 attempt returns an error, requests an IMDSv2 token with a six-hour TTL and repeats the role and credential requests with the token header.
3. Parses `AccessKeyId`, `SecretAccessKey`, and `Token` from the metadata response.
4. Prints all three credential values to standard output.

The current module-registry handler has a maturity defect: its success check is reversed, so credentials from a successful run are **not** saved into the interactive session's AWS credential field. Use `aws-enter-credentials` if a later interactive command must consume credentials reliably.

## Expected output

On success, output has this form:

```text
IAM Credentials for user <role-name> are:

aws_access_key_id = <access-key-id>
aws_secret_access_key = <secret-access-key>
aws_session_token = <session-token>
```

The IMDSv2 path currently does not populate the displayed account name. Verbose mode is especially sensitive: it also prints the IMDSv2 token and credential details.

## Side effects and cleanup

The command performs metadata-service requests, including an IMDSv2 token `PUT` when fallback is needed, and writes credentials to the terminal. It does not change instance metadata, IAM resources, or local credential files. Clear terminal capture, shell logs, and other collected output according to the assessment's handling requirements. The credentials expire according to AWS, although Peirates does not display or track their expiration.

## Failure modes

- IMDS is unreachable, disabled, or blocked by hop-limit or network policy.
- No IAM role is attached, or the metadata endpoints return a non-success status.
- A response cannot be read or decoded as the expected JSON.
- The IMDSv1 credential-detail request can return a non-success status as an empty credential result without an error; that prevents the normal IMDSv2 fallback and can produce blank output.
- The IMDSv2 implementation does not validate every response status and returns a nil error after some JSON-decoding failures, so blank credentials do not always mean success.
- The metadata HTTP client has no overall request timeout, so some network failures can wait on lower-level transport timeouts.

## Implementation and tests

- Handler and session integration: [`internal/app/module_registry.go`](../../internal/app/module_registry.go)
- IMDS retrieval and display: [`internal/app/aws.go`](../../internal/app/aws.go)
- Number and alias resolution: [`internal/app/dispatch.go`](../../internal/app/dispatch.go)
- Classic menu text: [`internal/app/menu.go`](../../internal/app/menu.go)
- IMDSv1, IMDSv2, and region tests: [`internal/app/aws_test.go`](../../internal/app/aws_test.go)
- `-m` smoke and alias coverage: [`internal/app/module_commands_test.go`](../../internal/app/module_commands_test.go)
