# Scan TCP ports

## Menu entry

- **Menu item:** 93
- **Canonical command:** `tcpscan`
- **Aliases:** `portscan`, `tcp scan`, `port scan`
- **Maturity:** Supported; CIDR mode is explicitly described as hidden and potentially slow

## Purpose

Attempt TCP connections to every port from 1 through 65535 on an IPv4 address. A hidden mode expands an IPv4 CIDR and scans every usable host.

## Prerequisites and authorization

The Peirates process needs network reachability to the targets. Port scanning can trigger monitoring or affect fragile services; scan only approved address ranges.

## Usage

```text
tcpscan
```

The command prompts for an IPv4 address or CIDR. It still prompts when started with `peirates -m tcpscan`, so it is not suitable for unattended one-shot use.

## What it does

For each target address, Peirates creates a worker pool and attempts all TCP ports with a 50-millisecond dial timeout. CIDR mode excludes the network and broadcast addresses and scans each remaining address sequentially.

## Expected output

Open ports are printed in ascending order as `IP:PORT open`. Connection failures are also currently printed by scan workers, so output can be very noisy.

## Side effects and cleanup

The scan creates a large number of outbound connections but does not intentionally modify targets. No cleanup is normally required.

## Failure modes

Input validation checks IPv4-shaped text but does not reject every octet above 255 before scanning. Large CIDRs can take a long time or consume substantial resources. Firewalls and the short timeout can make open ports appear closed.

## Implementation and tests

See [`menu_tcp_portscan.go`](../../internal/app/menu_tcp_portscan.go) and [`portscan.go`](../../internal/modules/portscan/portscan.go). CIDR and connection behavior are tested in [`portscan_test.go`](../../internal/modules/portscan/portscan_test.go), with wrapper coverage in [`portscan_test.go`](../../internal/app/portscan_test.go).
