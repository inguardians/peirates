# Agent 2 — model, token, and UI

Allowed files: new `internal/model/**`, `internal/token/**`, `internal/ui/**`, and the root production/tests being moved into those packages. Do not edit `internal/app`, `cmd/peirates`, module metadata, scripts, or docs.

Dependencies: begin with pure JWT/token extraction, then cohesive UI/output boundaries after the primary agent confirms interfaces.

Tests: move relevant tests with production code and run focused package tests plus `go test ./...` before handoff.

Handoff: report exported internal API, call-site changes needed, tests run, and unresolved coupling. Keep every intermediate state buildable where practical.

Non-goals: behavior changes, output cleanup, new public API, Kubernetes/cloud/module extraction, or dependency upgrades.
