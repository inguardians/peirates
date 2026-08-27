# Correct one-shot shell input behavior

## Exclusive ownership

- Target file: `docs/commands/shell.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page says one-shot mode returns after the first command. The handler executes the command supplied after `shell`, then continues reading and executing lines from standard input until `exit`, EOF, or an input error.

## Work

1. Correct the module-mode usage description.
2. Warn that piped standard input can execute additional commands.
3. Keep the distinction between direct `exec.Command` execution and shell-language parsing.

## Verification

- Compare the final wording with the loop in `internal/app/peirates.go`.
- Confirm the documented termination conditions match the implementation.
