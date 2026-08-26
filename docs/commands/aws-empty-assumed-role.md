# Deactivate the assumed AWS role

## Menu entry

- Number: `8`
- Canonical command: `aws-empty-assumed-role`
- Alias: `empty-aws-assumed-role`
- Maturity: Supported, with module smoke coverage; credential erasure is incomplete.

## Purpose

Stop later Peirates AWS operations from selecting the session's assumed-role credential set.

## Prerequisites and authorization

No AWS permission or network access is required. The command is meaningful only after an assumed role has been stored in the current Peirates process.

## Usage

At the interactive prompt, enter `8`, `aws-empty-assumed-role`, or `empty-aws-assumed-role`.

The command has no prompts and is suitable for module mode:

```sh
peirates -m aws-empty-assumed-role
```

Because a fresh module-mode process has no previously assumed role, that form is normally a no-op.

## What it does

Peirates sets the assumed credential set's access key ID and account name to empty strings. Later AWS operations test the access key ID before preferring assumed credentials, so they fall back to the available base credential set.

## Expected output

There is no command-specific success or status message. In interactive mode, the next banner no longer shows an assumed AWS credential context.

## Side effects and cleanup

The change is local to process memory and makes no AWS request. It does not revoke or expire the STS session at AWS.

Important: the implementation does **not** clear the assumed secret access key or session token from memory; it only makes that credential set inactive by clearing its access key ID. Exit Peirates to discard all in-memory credential fields.

## Failure modes

The handler has no error path. Its main limitation is incomplete erasure of the assumed credential material. Running it in a new `-m` process cannot affect a role held by another or earlier process.

## Implementation and tests

- [Registry handler](../../internal/app/module_registry.go)
- [Credential structure and AWS credential selection](../../internal/app/aws.go)
- [Dispatch aliases](../../internal/app/dispatch.go)
- [Module smoke tests](../../internal/app/module_commands_test.go)
