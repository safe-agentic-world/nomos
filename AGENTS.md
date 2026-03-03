# Repository Guidelines

## Project Structure & Module Organization
Nomos is a Go codebase with policy bundles, docs, deployment manifests, and test fixtures.

Key paths:
- `cmd/nomos`: CLI entrypoint (`version`, `serve`, `mcp`, `policy`, `doctor`)
- `internal/`: implementation packages (`action`, `policy`, `gateway`, `service`, `mcp`, `executor`, `audit`, `identity`, `doctor`, etc.)
- `policies/`: starter policy bundles (`minimal`, `safe-dev`, `safe-dev-hardened`, `guarded-prod`, `unsafe`)
- `docs/`: product, security, and deployment documentation
- `deploy/`: CI and Kubernetes reference artifacts
- `testdata/`: corpora, bypass fixtures, and CI config fixtures
- top-level configs: `config.example.json`, `config.all-fields.example.json`, `config.codex.json`

## Build, Test, and Development Commands
Primary commands:
- `go build ./cmd/nomos`: build the CLI
- `go test ./...`: run the full test suite
- `go vet ./...`: run Go static checks
- `go test ./internal/mcp`: focused MCP compatibility tests
- `go run ./cmd/nomos doctor -c ./config.example.json --format json`: deterministic readiness check

If you change workflows, keep `.github/workflows/ci.yml` green and preserve least-privilege defaults.

## Coding Style & Naming Conventions
Current conventions:
- follow standard Go formatting (`gofmt`)
- keep policy/config behavior deterministic and fail closed
- reject unknown fields unless the API explicitly allows extensions
- keep Markdown headings short and in Title Case
- use descriptive rule IDs in policy bundles and keep them stable

## Testing Guidelines
Tests are already in place across `cmd/` and `internal/`.

When changing behavior:
- add or update targeted unit tests near the affected package
- run at least the focused package tests plus `go test ./...`
- keep CI smoke checks passing, especially CLI/policy/doctor and MCP compatibility tests

## Commit & Pull Request Guidelines
Use short, imperative subject lines (for example, `Add safe-dev-hardened starter bundle`).

Pull requests should include:
- A concise summary of changes.
- Links to relevant issues or tasks.
- Notes on tests run (or why tests are not applicable).
- Documentation updates when behavior or structure changes.

## Security & Configuration Notes
Do not add secrets to the repository.

Configuration guidance:
- keep local developer configs separate from CI fixtures
- use checked-in, portable fixtures for CI under `testdata/ci/`
- prefer relative paths in sample configs unless a local-only config explicitly targets a workstation
