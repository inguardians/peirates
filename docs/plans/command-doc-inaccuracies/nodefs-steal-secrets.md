# Correct node-filesystem token disclosure documentation

## Exclusive ownership

- Target file: `docs/commands/nodefs-steal-secrets.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page says the module does not intentionally print service-account token strings. A projected token that does not have three JWT segments is included verbatim in the `Invalid token:` error emitted by `parseServiceAccountJWTReturnSub`.

## Work

1. Qualify the output-confidentiality statement so malformed projected token-file contents are disclosed by the current error path.
2. Add that behavior to failure modes and handling guidance.
3. Do not weaken the existing warning that normal findings and paths are sensitive.

## Verification

- Compare the final wording with `internal/app/config.go` and `internal/app/service_account_utils.go`.
- Ensure the page distinguishes valid-token behavior from malformed-token error behavior.
