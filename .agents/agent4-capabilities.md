# Agent 4 — cloud and modules

Allowed files: new `internal/cloud/**`, `internal/modules/**`, and corresponding root production/tests as they move. Do not edit `internal/app`, `cmd/peirates`, scripts, docs, or dependency metadata.

Dependencies: start with independent cloud-provider or pure local capability extraction. Attack modules and registry wait for Kubernetes/app handoff contracts.

Tests: move relevant tests with code, add boundary tests where state crosses packages, and run focused tests plus `go test ./...` before handoff.

Handoff: report APIs/state required from app and kube, aliases/handlers covered, tests run, and remaining coupled code.

Non-goals: CLI/session ownership, shared integration files, provider behavior changes, dependency upgrades, or release changes.
