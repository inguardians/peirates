# Run a local command

## Menu entry

- **Menu item:** Unnumbered
- **Canonical command:** `shell`
- **Maturity:** Supported

## Purpose

Execute an operating-system program from the Peirates process environment.

## Prerequisites and authorization

The requested executable must exist and be runnable inside the current container or host environment. This feature intentionally provides arbitrary command execution; use it only on systems where that access is authorized.

## Usage

```text
shell id
shell uname -a
```

```sh
peirates -m 'shell id'
```

Bare `shell` prompts for an initial command. After running an initial command, the handler continues reading commands from standard input; subsequent lines do not need the `shell` prefix. The loop stops when a subsequent line is `exit` or empty, or when reading standard input reaches EOF or returns an error.

This behavior also applies to module mode. `peirates -m 'shell id'` can execute additional commands supplied through piped or redirected standard input before it returns; it does not necessarily stop after `id`.

## What it does

Peirates splits the input on whitespace, treats the first field as the executable, and runs it directly with `exec.Command`. It does not invoke a shell interpreter for `shell <command>`.

## Expected output

Combined stdout and stderr are printed and can be appended to the configured output file.

## Side effects and cleanup

The executed program has the same filesystem, network, and operating-system access as Peirates and may make arbitrary local or remote changes. Cleanup depends entirely on the command that was run.

## Failure modes

Shell operators, pipelines, redirects, globbing, variable expansion, and quoted arguments are not interpreted. A missing executable or nonzero exit prints an execution error.

## Implementation and tests

See the direct command handler in [`peirates.go`](../../internal/app/peirates.go). One-shot behavior is tested in [`module_commands_test.go`](../../internal/app/module_commands_test.go).
