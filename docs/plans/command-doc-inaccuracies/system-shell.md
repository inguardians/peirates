# Correct noninteractive system-shell guidance

## Exclusive ownership

- Target file: `docs/commands/system-shell.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page says `bash` and `sh` require an interactive terminal and should not be used through `-m` for unattended execution. The child shell inherits standard input and can execute a piped script without a terminal, then exit at EOF.

## Work

1. Explain interactive terminal use and piped noninteractive use separately.
2. State that an open stdin can leave the child waiting, while closed stdin can make it exit immediately.
3. Preserve the privilege and cleanup warnings.

## Verification

- Compare the final wording with `internal/modules/shell/shell.go`.
- Ensure usage no longer categorically says a terminal is required.
