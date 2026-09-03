# Agent 1 — integration and baseline

Owner: primary agent.

Scope: Phase 0 baseline, characterization tests, `cmd/peirates`, `internal/app`, shared integration, and final verification. Own shared files including `go.mod`, `go.sum`, `Makefile`, scripts, and documentation.

Dependencies: leaf-package interfaces must be handed off before integration. Sequence all edits to shared files.

Tests: baseline `gofmt`, `go vet ./...`, `go test ./...`, build `./cmd/peirates`, scripts/build.sh, and compatibility tests.

Handoff: publish interfaces and state needs to leaf owners; integrate only after their focused tests pass.

Non-goals: cloud, Kubernetes, UI/token, and module implementation files except temporary adapters strictly needed for buildability.
