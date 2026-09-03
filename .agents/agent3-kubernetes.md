# Agent 3 — Kubernetes capabilities

Allowed files: new `internal/kube/**`, Kubernetes-specific root production/tests being moved, and narrowly shared types under `internal/model/**` only after coordination with Agent 2. Do not edit `internal/app`, `cmd/peirates`, scripts, docs, or dependency metadata.

Dependencies: inventory transport and injection seams first. Extract transport/kubectl before credentials, enumeration, and execution. Coordinate shared model types before editing them.

Tests: preserve existing request, credential, enumeration, kubectl, and execution tests; run focused tests and `go test ./...` before handoff.

Handoff: report APIs needed by app/modules, preserved hooks, tests run, and remaining root callers.

Non-goals: CLI/session integration, cloud/local/attack modules, behavior fixes, or dependency changes.
