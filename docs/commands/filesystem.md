# Filesystem commands

## Menu entry

- **Menu item:** Unnumbered grouped row
- **Canonical commands:** `cd`, `pwd`, `ls`, `cat`
- **Maturity:** Supported with intentionally limited syntax

## Purpose

Inspect and navigate the filesystem visible to the Peirates process without requiring external coreutils programs.

## Prerequisites and authorization

The process needs operating-system permission to access each path. In a container, the visible filesystem and any mounted host paths determine what can be read.

## Usage

```text
pwd
ls
ls /var/run/secrets
cd /tmp
cat /path/to/file
```

Each form also works as one-shot input, for example `peirates -m 'ls /tmp'`.

## What it does

`pwd` prints the process working directory. `cd` changes that directory for the current process. `ls` prints entry names for the current directory or each supplied directory. `cat` prints each supplied file in order.

## Expected output

Paths, directory entry names, or file contents are printed directly to the terminal.

## Side effects and cleanup

`cd` changes Peirates' working directory for the rest of the session. The other commands are read-only. File contents may include credentials or other sensitive data and are not automatically redacted.

## Failure modes

Paths containing spaces are not handled reliably because arguments are split on whitespace. `ls` rejects flags, does not provide metadata, and does not sort or format like system `ls`. Permission and missing-path errors are printed.

## Implementation and tests

See the dispatcher in [`peirates.go`](../../internal/app/peirates.go) and helpers in [`filesystem.go`](../../internal/modules/filesystem/filesystem.go). Coverage is in [`filesystem_test.go`](../../internal/modules/filesystem/filesystem_test.go), [`filesystem_manipulation_test.go`](../../internal/app/filesystem_manipulation_test.go), and [`module_commands_test.go`](../../internal/app/module_commands_test.go).
