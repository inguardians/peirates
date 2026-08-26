# Write supported output to a file

## Menu entry

- **Menu item:** `outputfile`
- **Canonical command:** `outputfile`
- **Maturity:** Alpha

## Purpose

Append output from supported Peirates operations to a local file while continuing to display it in the terminal.

## Prerequisites and authorization

The Peirates process needs write access to the requested path. Choose a protected location because captured kubectl or HTTP output may contain secrets.

## Usage

```text
outputfile results.log
kubectl get pods
outputfile
```

`outputfile <filename>` enables logging and bare `outputfile` disables it. The filename cannot contain spaces. One-shot `peirates -m 'outputfile results.log'` exits immediately after changing the in-memory setting, so it cannot capture a later one-shot command.

## What it does

Peirates stores the filename and enables a session flag. Operations routed through the shared output helper print normally and append raw output to the file with mode `0600` when it must be created.

## Expected output

Enabling prints `Output file set to:` and the name. Disabling reports that output-to-file is deactivated. Existing files are appended rather than truncated.

## Side effects and cleanup

The command can create or append to a local file containing sensitive data. Disable logging with bare `outputfile`; securely remove or archive the file according to the engagement's data-handling rules.

## Failure modes

Filenames containing spaces are rejected. Directory, permission, and open/write errors are reported when output is written. Not every direct `println` in Peirates uses the shared output helper, so this is not a complete session transcript.

## Implementation and tests

See the dispatcher in [`peirates.go`](../../internal/app/peirates.go) and [`output.go`](../../internal/ui/output.go). Behavior is tested in [`module_commands_test.go`](../../internal/app/module_commands_test.go) and [`output_test.go`](../../internal/ui/output_test.go).
