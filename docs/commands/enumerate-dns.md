# Enumerate Kubernetes services through DNS

## Menu entry

- **Menu item:** 94
- **Canonical command:** `enumerate-dns`
- **Maturity:** Alpha; depends on legacy wildcard DNS behavior

## Purpose

Attempt to enumerate Kubernetes Services using a wildcard SRV lookup from the cluster network.

## Prerequisites and authorization

Peirates must be able to query cluster DNS and resolve service targets. The cluster DNS implementation must support the wildcard query used by this command.

## Usage

```text
enumerate-dns
```

```sh
peirates -m enumerate-dns
```

## What it does

Peirates queries the SRV name `any.any.svc.cluster.local`, resolves the first IP for each returned target, prints service endpoints, and builds a suggested nmap command from the unique names and ports.

## Expected output

Each result is printed as a service DNS name, IP address, and port, followed by a suggested nmap command.

## Side effects and cleanup

The command sends DNS queries only and does not run the suggested nmap scan. No cleanup is required.

## Failure modes

Modern CoreDNS configurations commonly do not support the wildcard behavior, producing no results and an error that references CoreDNS 1.9.0 or later. Individual targets that do not resolve are skipped.

## Implementation and tests

See [`enumerate_dns.go`](../../internal/app/enumerate_dns.go) and the newer DNS module in [`dns.go`](../../internal/modules/dns/dns.go). DNS result handling is tested in [`dns_test.go`](../../internal/modules/dns/dns_test.go), and dispatch coverage is in [`module_commands_test.go`](../../internal/app/module_commands_test.go).
