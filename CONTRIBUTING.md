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

## Pull Requests

Please include:

- what changed and why
- linked issue/task (if any)
- tests run and results
- docs updates when behavior changes

## Rules

- Keep policy behavior deterministic and deny-by-default.
- Do not introduce secret logging.
- Keep validation strict (reject unknown fields unless explicitly allowed).
- Prefer small, focused changes.
