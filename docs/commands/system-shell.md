# Start a system shell

## Menu entry

- **Menu item:** Unnumbered grouped row
- **Canonical commands:** `bash`, `sh`
- **Maturity:** Supported when the selected shell exists

## Purpose

Start an interactive Bash or Bourne-compatible shell attached to Peirates' standard input, output, and error streams.

## Prerequisites and authorization

`bash` requires `/bin/bash`; `sh` requires `/bin/sh`. The spawned shell inherits Peirates' operating-system privileges and environment.

## Usage

```text
bash
sh
```

These commands require an interactive terminal. Do not use `peirates -m bash` or `peirates -m sh` for unattended execution; the child shell waits on standard input.

## What it does

Peirates starts the selected absolute shell path as a child process and connects it directly to the current standard streams. Returning from the child shell resumes Peirates.

## Expected output

The selected shell provides its normal prompt and output. Peirates prints an error if the shell cannot be started.

## Side effects and cleanup

Shell commands can make arbitrary changes with Peirates' privileges. Type `exit` in the child shell to return to Peirates, and separately clean up any resources or files created there.

## Failure modes

Minimal container images may not contain `/bin/bash`; use `sh` when `/bin/sh` is available. Non-interactive stdin can cause the shell to exit immediately or hang.

## Implementation and tests

See [`run_external_programs.go`](../../internal/app/run_external_programs.go), [`module_registry.go`](../../internal/app/module_registry.go), and [`shell.go`](../../internal/modules/shell/shell.go). Process execution is tested in [`shell_test.go`](../../internal/modules/shell/shell_test.go).
