# Configure authorization prechecks

## Menu entry

- **Menu item:** 92
- **Canonical command:** `set-auth-can-i`
- **Maturity:** Supported session setting

## Purpose

Choose whether Peirates asks Kubernetes if the current identity can perform an operation before attempting selected actions.

## Prerequisites and authorization

No additional privilege is required to open the setting menu. When enabled, the current Kubernetes identity must be able to submit the relevant self-subject access review for the check to be useful.

## Usage

```text
set-auth-can-i
```

Choose `true`, `false`, or `exit` at the submenu. Numeric and short forms `1`/`t` and `0`/`f` are also accepted. The command always prompts, including when invoked as `peirates -m set-auth-can-i`, so it is not an unattended one-shot command.

## What it does

The command updates the in-memory `UseAuthCanI` setting for the current Peirates session. `false` skips supported preflight checks; it does not grant any permission or bypass API-server authorization.

## Expected output

Peirates displays the current value and the available choices. It does not print a separate confirmation after a valid selection.

## Side effects and cleanup

The setting affects only the running Peirates process and disappears on exit. Disabling checks may cause Peirates to attempt actions that the server subsequently denies.

## Failure modes

EOF, an interrupted prompt, or `exit` leaves the value unchanged. Unrecognized input also returns without changing the setting.

## Implementation and tests

See [`menu_use_auth_cani.go`](../../internal/app/menu_use_auth_cani.go) and its registry entry in [`module_registry.go`](../../internal/app/module_registry.go). Completion coverage is in [`module_commands_test.go`](../../internal/app/module_commands_test.go).
