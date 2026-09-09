# Contributing To Nomos

Nomos is an Apache-2.0 open-source project focused on permission tests and
human approval for custom agent tools. Start by running the
[local inbox demo](docs/quickstart.md), then pick a small improvement from
[the roadmap](docs/roadmap.md).

## Useful Contributions

- A reproducible permission bug with the smallest policy and action fixture.
- A complete custom-tool integration with a local, account-free test path.
- A denial, approval-expiry, retry, or changed-arguments regression test.
- A quickstart improvement verified from a fresh environment.

Discuss new frameworks or substantial abstractions in an issue first.
We are not expanding into cluster deployment, hosted dashboards, or a
general enterprise control plane.

## Development

The CLI is in `cmd/nomos`; policy, gateway, approval, and execution logic
are in `internal/`. Public Go clients live in `pkg/sdk`; Python and
TypeScript sources in `sdk/`. The primary runnable example is
`examples/local-inbox`.

Use standard Go naming and `gofmt`. Keep behavior deterministic and
fail closed. Python uses four-space indentation and standard-library
`unittest`; name tests `test_*.py`. Add optional framework dependencies
as extras, not base SDK requirements. Keep policy rule IDs descriptive and
stable; reject unknown fields unless a contract explicitly allows them.

Run focused tests, then `go test ./...`, `go vet ./...`, and the
relevant SDK/integration commands in [TESTING.md](TESTING.md).
There is no mandatory coverage percentage; meaningful failure-path
assertions are required for behavior changes.

## Pull Requests

Use a focused imperative subject, following existing conventions such as
`fix: reject expired tool approvals` or `feat: add ticket permission fixtures`.
Include the problem, linked issue if any, scope, tests actually run, and
migration notes for behavior changes. Include screenshots only for UI
changes. Do not claim unrun tests passed.

Keep generated binaries, Python caches, local databases, credentials, and
temporary demo artifacts out of commits. Preserve existing contributor
instructions in `AGENTS.md`.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not a
public issue containing secrets or an exploitable production configuration.
