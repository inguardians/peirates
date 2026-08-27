# Assume an AWS role

## Menu entry

- Number: `7`
- Canonical command: `aws-assume-role`
- Aliases: none beyond numeric entry `7`
- Maturity: Supported, but only ARN rejection and module smoke behavior are tested locally; there is no live STS integration test.

## Purpose

Use the session's available AWS credentials to request temporary credentials for another IAM role through AWS STS.

## Prerequisites and authorization

The current Peirates process must have base AWS credentials, loaded from environment variables at startup or entered through `aws-enter-credentials`. Those credentials need `sts:AssumeRole` permission for the target, and the target role's trust policy must accept the caller.

Peirates also determines the AWS region through EC2 Instance Metadata Service (IMDS), so this implementation requires network access to a working IMDS endpoint even though STS itself can otherwise be used away from EC2.

## Usage

At the interactive prompt, enter `7` or `aws-assume-role`, then provide a role ARN such as:

```text
arn:aws:iam::123456789012:role/roleName
```

Module mode is supported but still reads the ARN from stdin:

```sh
peirates -m aws-assume-role
```

For module mode, supply base credentials through `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, plus `AWS_SESSION_TOKEN` when the source credentials are temporary. Credentials manually entered in a previous Peirates process are not retained.

## What it does

Peirates validates the ARN, queries IMDS for the availability zone to derive a region, creates an AWS SDK STS client with the base credentials, and calls `AssumeRole` with session name `sts_session`. On success it stores the returned access key, secret key, session token, and role ARN in the session's assumed-role slot. Later supported AWS actions prefer this assumed role when its access key ID is non-empty.

## Expected output

The command prompts for the ARN. When base credentials come from environment variables, Peirates also prints those credentials in plaintext during startup. A successful STS request prints the SDK's assumed-role-user and credential structures, including the temporary access key ID, secret access key, and session token in plaintext. Failures report invalid input, inability to obtain a region, session creation failure, or STS assume-role failure.

## Side effects and cleanup

This command makes network requests to IMDS and AWS STS and retains temporary credentials in memory. It does not change the source credentials or modify the IAM role. Use `aws-empty-assumed-role` to deactivate the assumed context. Treat every successful command's terminal or log output as containing the complete temporary credential set, and protect or securely remove that output.

## Failure modes

- No explicit check ensures that base credentials are populated before the STS call.
- The accepted ARN regex is narrower than AWS role syntax and unanchored: paths and many valid punctuation characters may be rejected, while a matching substring may be accepted.
- IMDS unavailability or malformed availability-zone output prevents role assumption.
- AWS authentication, authorization, trust-policy, endpoint, or network errors cause the STS request to fail.
- Module mode is only useful when base credentials are available at that process's startup.

## Implementation and tests

- [Role prompt, STS request, and credential storage](../../internal/app/aws.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [AWS unit tests](../../internal/app/aws_test.go)
- [Module smoke tests](../../internal/app/module_commands_test.go)
