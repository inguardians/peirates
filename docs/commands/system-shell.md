# Start a system shell

## Menu entry

- **Menu item:** Unnumbered grouped row
- **Canonical commands:** `bash`, `sh`
- **Maturity:** Supported when the selected shell exists

## Purpose

Start Bash or a Bourne-compatible shell attached to Peirates' standard input, output, and error streams. With a terminal, the shell can be used interactively; with piped standard input, it can run a script noninteractively.

## Prerequisites and authorization

`bash` requires `/bin/bash`; `sh` requires `/bin/sh`. The spawned shell inherits Peirates' operating-system privileges and environment.

## Usage

```text
bash
sh
```

Use `bash` or `sh` from an interactive Peirates session to start a shell on the current terminal. For noninteractive execution, pipe a script to a one-shot command, for example:

```sh
printf 'id\nuname -a\n' | peirates -m sh
```

The child shell reads from Peirates' standard input. A pipe closes at EOF after the script is written, allowing the shell to exit. If standard input remains open, the shell may keep waiting for more commands; if it is already closed, the shell may exit immediately.

## What it does

Peirates starts the selected absolute shell path as a child process and connects it directly to the current standard streams. Returning from the child shell resumes Peirates.

## Expected output

On a terminal, the selected shell provides its normal prompt and output. With piped input, it normally prints only the script's output and diagnostics, without an interactive prompt. Peirates prints an error if the shell cannot be started.

## Side effects and cleanup

Shell commands can make arbitrary changes with Peirates' privileges. Type `exit` in the child shell to return to Peirates, and separately clean up any resources or files created there.

## Failure modes

Minimal container images may not contain `/bin/bash`; use `sh` when `/bin/sh` is available. A child shell can wait indefinitely when standard input remains open without supplying more commands, while closed standard input can make it exit immediately.

## Implementation and tests

See [`run_external_programs.go`](../../internal/app/run_external_programs.go), [`module_registry.go`](../../internal/app/module_registry.go), and [`shell.go`](../../internal/modules/shell/shell.go). Process execution is tested in [`shell_test.go`](../../internal/modules/shell/shell_test.go).
