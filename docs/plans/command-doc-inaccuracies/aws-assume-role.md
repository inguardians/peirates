# Correct AWS assume-role credential-output documentation

## Exclusive ownership

- Target file: `docs/commands/aws-assume-role.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page says the AWS SDK redacts the assumed role's secret access key. In AWS SDK v1.42.4, `sts.Credentials` does not tag `SecretAccessKey` or `SessionToken` as sensitive, while `AWSSTSAssumeRole` prints the credential structure. Both values are therefore exposed in plaintext on success.

## Work

1. Correct the expected-output description to state that the access key ID, secret access key, and session token can all be printed.
2. Strengthen the cleanup guidance to treat successful output as containing the complete temporary credential set.
3. Preserve the existing structure and implementation links.

## Verification

- Compare the final wording with `internal/app/aws.go` and the generated AWS SDK `sts.Credentials` type.
- Review the diff for claims that still imply redaction.
