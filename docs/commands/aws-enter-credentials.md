# Enter AWS credentials

## Menu entry

- Number: `6`
- Canonical command: `aws-enter-credentials`
- Aliases: `enter-aws-credentials`, `aws-creds`
- Maturity: Supported, with unit and module smoke coverage but no live AWS integration test in this repository.

## Purpose

Manually install AWS access-key credentials in the current Peirates session for later AWS operations.

## Prerequisites and authorization

You need an AWS access key ID, secret access key, session token, and a local name/comment. Their actual AWS permissions determine which later actions succeed. Treat all values as sensitive credentials and use them only with authorization.

## Usage

At the interactive prompt, enter `6`, `aws-enter-credentials`, or an alias, then answer all four prompts.

Module mode is supported but still reads all values from stdin:

```sh
peirates -m aws-enter-credentials
```

Because module mode exits immediately afterward, manually entered credentials are normally useful only in an interactive Peirates session; a later Peirates process does not inherit them.

## What it does

Peirates reads and validates four whitespace-delimited values, uppercases the access key ID, stores the resulting credential set in session memory, and immediately calls its credential display routine.

## Expected output

On success, Peirates prints the selected name followed by the access key ID, **secret access key, and session token in plaintext**. On validation failure it reports the component that was rejected and leaves the prior session credentials unchanged.

## Side effects and cleanup

Successful entry replaces the session's available (non-assumed) AWS credentials. It makes no AWS request and writes no configuration file, but it exposes every credential component to stdout, terminal scrollback, and any surrounding output capture. Exit Peirates to discard the in-memory values and securely clear any captured output.

## Failure modes

- Empty input or stdin EOF aborts entry.
- Access key ID and secret key must each match at least 18 `\w` characters; the session token needs at least five and the name at least one.
- These regexes are not faithful AWS credential validation: for example, valid secret/session-token characters such as `/`, `+`, or `=` are not matched as part of `\w`, while unanchored substrings can pass.
- `fmt.Scanln` makes values containing whitespace unsuitable.
- No live AWS call verifies that the credentials are valid or active.

## Implementation and tests

- [Credential input, validation, and display](../../internal/app/aws.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/aws_test.go)
- [Module smoke tests](../../internal/app/module_commands_test.go)
