# Document arbitrary HTTP methods in direct curl mode

## Exclusive ownership

- Target file: `docs/commands/curl.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page describes the command as making GET or POST requests. Only the wizard enforces those methods; direct `curl -X METHOD URL` accepts any method string and passes it to `http.NewRequest`, including destructive methods such as DELETE.

## Work

1. Distinguish the wizard's GET/POST restriction from direct mode's arbitrary `-X` behavior.
2. Add a direct-mode example or warning that makes the broader method surface clear.
3. Update side-effect or failure guidance so operators do not infer that direct mode is limited to GET and POST.

## Verification

- Compare the final wording with `curlNonWizard` and `createHTTPrequest` in `internal/app/http_utils.go`.
- Ensure no remaining statement applies the wizard restriction to direct mode.
