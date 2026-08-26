# Command name

## Menu entry

- **Menu item:** Number or label
- **Canonical command:** `command-name`
- **Aliases:** `alias-one`, `alias-two`
- **Maturity:** Stable, alpha, incomplete, or another status supported by the code

## Purpose

Explain the outcome of the command and when an authorized operator would use it.

## Prerequisites and authorization

List required Peirates state, Kubernetes or cloud permissions, network access, and local tools or paths.

## Usage

Show interactive input and, when supported, one-shot usage with `peirates -m`. State clearly when a command still prompts for input or is unsuitable for unattended use.

## What it does

Describe the important implementation behavior in execution order without promising behavior the code does not provide.

## Expected output

Describe recognizable success output and where sensitive results are stored or displayed.

## Side effects and cleanup

Call out created workloads, changed authentication state, filesystem writes, network traffic, remote changes, and cleanup steps. Use an explicit warning for disruptive commands.

## Failure modes

List common errors, permission failures, environmental limitations, and any implementation quirks.

## Implementation and tests

Link to the source handler and the most relevant unit or integration tests using paths relative to this page.
