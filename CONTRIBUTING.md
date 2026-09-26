# Contributing To Nomos

Nomos is an Apache-2.0 project that decides, deterministically and before
execution, whether an AI coding agent's shell, file, or tool call is
allowed, denied, or needs a human. The fastest way to help is to make the
decisions better on real commands.

## Contributions That Matter Most

- **A bypass.** A command, path spelling, or wrapper that the Claude Code
  hook allowed but should not have. Open a
  [bypass report](https://github.com/safe-agentic-world/nomos/issues/new?template=bypass_report.yml)
  with the exact `--simulate` output; confirmed bypasses become cases in
  `examples/incidents/` and a regression test.
- **A noisy decision.** A benign, in-workspace command that a default
  profile denies or asks about. Open a
  [noisy decision report](https://github.com/safe-agentic-world/nomos/issues/new?template=noisy_decision.yml);
  these tune the profiles without loosening the incident cases.
- **An incident case.** A destructive or secret-reading command from a real
  agent incident (link the public report) added to the incident suites so it
  stays denied or reviewed forever.
- **A first-run report.** Reproduce the README quickstart on a fresh machine
  and report the exact step that failed or confused you.
- **A harness contract.** Primary-source details (file path, quote) of how
  another coding agent's pre-tool hook receives and returns decisions.

Questions, policy examples, and ideas belong in
[Discussions](https://github.com/safe-agentic-world/nomos/discussions).
Discuss new frameworks or substantial abstractions in an issue first. We
are not expanding into cluster deployment, hosted dashboards, or a general
enterprise control plane.

## Development

Go 1.25+. The CLI is in `cmd/nomos`; the hook adapter is in
`internal/agenthook`; policy, gateway, approval, and execution logic are in
`internal/`. Public Go clients live in `pkg/sdk`; Python and TypeScript
sources in `sdk/`. Default profiles are in `profiles/` and are embedded at
build time: after editing one, run `go run scripts/pin_profile_hashes.go`
to refresh the embedded copy and the pinned hashes. A profile change also
moves decisions on the real-world corpus: regenerate the golden with
`go test ./internal/agenthook -run Corpus -update-corpus` and review every
changed line of `testdata/realworld/expected.json` in your diff.

Fast iteration:

```bash
go test ./cmd/nomos ./internal/policy ./internal/agenthook
go build ./cmd/nomos && ./nomos hook claude-code --simulate --profile safe-dev --command "rm -rf ~/"
```

Before a pull request: `gofmt -w .`, `go vet ./...`, `go test ./...`, and
`python3 scripts/check_docs.py`. `go test -race ./...` is the release gate.
Python uses four-space indentation and standard-library `unittest`; name
tests `test_*.py`. Keep behavior deterministic and fail closed. Keep policy
rule IDs descriptive and stable; reject unknown fields unless a contract
explicitly allows them. There is no mandatory coverage percentage;
meaningful failure-path assertions are required for behavior changes.

## Pull Requests

Use a focused imperative subject with a conventional prefix, such as
`fix: reject expired tool approvals` or `feat: add ticket permission
fixtures`. A merge whose title starts with `feat:` releases a minor version
and `fix:` a patch, automatically. Other prefixes, such as `docs:` and
`chore:`, do not release. Fill in the pull request template: the
problem, the change, the commands you actually ran with their results, and
migration notes for behavior changes. Do not claim unrun tests passed.

Keep generated binaries, Python caches, local databases, credentials, and
temporary demo artifacts out of commits. Preserve existing contributor
instructions in `AGENTS.md`.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not in a
public issue.
