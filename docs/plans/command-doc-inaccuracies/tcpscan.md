# Document invalid CIDR prefix panic

## Exclusive ownership

- Target file: `docs/commands/tcpscan.md`
- Do not edit any other command-reference page.

## Inaccuracy

The failure-mode discussion omits that the input regex accepts CIDR prefixes from 33 through 39. `CIDRHosts` then passes those values to `net.ParseCIDR` and panics on the returned error.

## Work

1. Add the accepted-invalid-prefix behavior and process panic to failure modes.
2. Keep the existing warnings about oversized CIDRs and invalid octets.
3. Do not imply that all syntactically matched CIDRs are safe to scan.

## Verification

- Compare the final wording with `internal/app/menu_tcp_portscan.go` and `internal/modules/portscan/portscan.go`.
- Confirm that `/33` through `/39` are described precisely.
