# Contributing

Thanks for contributing to Nomos.

## Development Setup

1. Install Go (version from `go.mod`).
2. Build:

```bash
go build ./cmd/nomos
```

3. Test:

```bash
go test ./...
go vet ./...
```

4. Workflow changes:

- keep GitHub Actions least-privilege (`contents: read` by default, elevate only per job)
- validate workflow changes with `Workflow Lint` and keep release changes PR-safe
- keep release automation workflow-driven; do not add manual release-only steps to docs or process

## Pull Requests

Please include:

- what changed and why
- linked issue/task (if any)
- tests run and results
- docs updates when behavior changes
- whether workflow/release behavior changed, if applicable

## Rules

- Keep policy behavior deterministic and deny-by-default.
- Do not introduce secret logging.
- Keep validation strict (reject unknown fields unless explicitly allowed).
- Prefer small, focused changes.
- Do not bypass the workflow-managed release path for tags, releases, or install-manifest updates.
