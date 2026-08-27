# Correct DNS test-coverage claim

## Exclusive ownership

- Target file: `docs/commands/enumerate-dns.md`
- Do not edit any other command-reference page.

## Inaccuracy

The page says the registered command's DNS result handling is tested by `internal/modules/dns/dns_test.go`. The registry actually calls the separate implementation in `internal/app/enumerate_dns.go`; the cited tests exercise a duplicate module implementation rather than the handler used by this command.

## Work

1. Correct the implementation-and-tests section to distinguish the registered implementation from the separately tested module.
2. State accurately that dispatch is covered but the active DNS enumeration implementation lacks focused result-handling tests.
3. Keep both source links if they help explain the duplication.

## Verification

- Compare `internal/app/module_registry.go`, `internal/app/enumerate_dns.go`, and `internal/modules/dns/dns_test.go`.
- Ensure the final page does not imply that the duplicate module's tests cover the registered handler.
