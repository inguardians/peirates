# Exit Peirates

## Menu entry

- **Menu item:** `exit`
- **Canonical command:** `exit`
- **Alias:** `quit`
- **Maturity:** Supported

## Purpose

Terminate the current Peirates process.

## Prerequisites and authorization

None.

## Usage

```text
exit
```

`quit`, end-of-file, or an interrupt at an empty prompt also leave the interactive loop. `peirates -m exit` and `peirates -m quit` terminate one-shot execution.

## What it does

The registered `exit` and `quit` handler calls `os.Exit(0)`. EOF or an empty-line interrupt exits through the surrounding menu loop.

## Expected output

No command-specific success message is printed.

## Side effects and cleanup

In-memory contexts and settings are discarded. Exit does not remove workloads, files, credentials exported to disk, or other changes made by earlier commands; clean those up before leaving when required.

## Failure modes

There are no expected command failures. A child shell or another blocking operation must return control before the main menu can process `exit`.

## Implementation and tests

See [`module_registry.go`](../../internal/app/module_registry.go), the loop in [`peirates.go`](../../internal/app/peirates.go), and alias handling in [`dispatch.go`](../../internal/app/dispatch.go). One-shot behavior is covered by [`module_commands_test.go`](../../internal/app/module_commands_test.go).
