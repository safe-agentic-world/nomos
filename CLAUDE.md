# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Go 1.25+. Use Makefile targets or `go` directly.

- Build CLI: `go build ./cmd/nomos` (or `make build`)
- Release build with version metadata: `make release-build` (sets ldflags into `internal/version`)
- Full test suite: `go test ./...`
- Race suite (release gate): `go test -race ./...`
- Static checks: `go vet ./...` (aliased as `make lint`)
- Format: `gofmt -w .` (aliased as `make fmt`)
- Single package: `go test ./internal/policy`
- Single test: `go test ./internal/policy -run TestName`
- Focused MCP compat: `go test ./internal/mcp`
- Fast iteration set: `go test ./cmd/nomos ./internal/policy ./internal/service ./internal/gateway ./internal/mcp ./internal/agenthook`
- Hook adapters: `go test ./internal/agenthook ./cmd/nomos`
- Corpus golden: `go test ./internal/agenthook -run Corpus`; after an intended decision change, regenerate with `-update-corpus` and review the diff of `testdata/realworld/expected.json`
- Profile hashes: `go run scripts/pin_profile_hashes.go` (or `make pin-profile-hashes`) after editing `profiles/*.yaml`
- Docs links: `python3 scripts/check_docs.py`

Smoke checks using the built binary (run after `make build` / `go build`):

- `nomos doctor -c ./examples/quickstart/config.quickstart.json --format json`
- `nomos policy test --action ./examples/quickstart/actions/allow-readme.json --bundle ./examples/policies/safe.yaml`
- `nomos policy test --action ./examples/quickstart/actions/deny-env.json --bundle ./examples/policies/safe.yaml`
- `nomos policy explain ...` for deny/approval diagnostics

CLI flag precedence is `flag > env > fail`. Relevant env vars: `NOMOS_CONFIG`, `NOMOS_POLICY_BUNDLE`, `NOMOS_LOG_LEVEL`. `--config/-c` and `--policy-bundle/-p` are resolved to absolute paths at parse time.

## Architecture

Nomos is an execution firewall for AI agents: an agent-agnostic control plane that sits at the execution boundary and returns `ALLOW` / `DENY` / `REQUIRE_APPROVAL` on normalized actions. The same pipeline backs both the MCP server and HTTP gateway surfaces — understanding that pipeline is the big picture.

**Request pipeline** (same shape whether the caller is MCP or HTTP):

1. **Boundary** (`internal/mcp` or `internal/gateway`) accepts the request. Identity is never read from the request body — it is injected from config and verified via bearer/HMAC/OIDC. The MCP path derives `action_id`/`trace_id` from the MCP request id (`mcp_<id>`) to stay deterministic.
2. **Normalize** (`internal/normalize`, `internal/action`) canonicalizes resources (e.g., `file://workspace/...`, `url://host/path`), rejects traversal (`..`), and yields a stable action fingerprint. Agent-supplied principal/environment claims are rejected.
3. **Policy evaluation** (`internal/policy`) is **deny-wins** and rule order is irrelevant. Bundles load from JSON or YAML; YAML is validated strictly (duplicate-key and unknown-field rejection) and `policy_bundle_hash` is always computed from canonical JSON of the typed bundle so equivalent inputs stay deterministic. Matching supports glob patterns and optional identity/risk filters.
4. **Obligations**: redaction patterns, output caps (`output_max_bytes`/`output_max_lines`), sandbox profile (`sandbox_mode`), approval scope. Sandbox selection is obligation-driven and fails closed when the configured profile is weaker than required.
5. **Approvals** (`internal/approval`) bind to exact action fingerprints by default; class-scoped approvals require explicit `approval_scope_class` obligation and are limited to `action_type_resource`.
6. **Execute** (`internal/executor`, `internal/sandbox`) runs only ALLOW decisions. `repo.apply_patch` is implemented as deterministic `path` + `content` replacement, not diff application. `net.http_request` maps normalized `url://` to `https://`, enforces host allowlists, and denies redirects unless the matched policy sets `http_redirects`.
7. **Credentials** (`internal/credentials`) are brokered as short-lived lease IDs bound to `(principal, agent, environment, trace_id)`. Raw secrets never return to the agent; only lease IDs surface in visibility.
8. **Redact + cap** (`internal/redact`) applies before any output leaves Nomos — to the agent, logs, and audit sinks. Per-rule caps are enforced post-redaction so policy caps cannot be bypassed by larger executor defaults.
9. **Audit + telemetry** (`internal/audit`, `internal/telemetry`): `action.completed` is the canonical replay-level `AuditEvent v1` record. Hash chaining runs over canonicalized payloads with `prev_event_hash` attached for cross-platform-deterministic verification. Telemetry is additive (OTLP/HTTP) — audit remains the authoritative evidence surface.

**Coding-agent hooks** (`internal/agenthook`): `nomos hook claude-code` and `nomos hook codex` decide an agent's native tool calls before they run. A shell parser splits command lists, unwraps `bash -c` and similar wrappers, and refuses syntax it cannot resolve statically (substitution, heredocs, most expansions) instead of guessing. Every path, including a program started by a relative path, is checked against the workspace lexically and physically from every directory the command could run in. Calls map to `process.exec`, `fs.read`, `fs.write`, `net.http_request`, or `mcp.call` actions and go through the same deny-wins engine; decisions are appended to a hash-chained audit file under `.nomos/`. Codex's `PreToolUse` cannot ask, so an ask is a deny there by default (`--ask passthrough` leaves it to Codex), and Nomos never answers a Codex `PermissionRequest` with allow. Replay (`--replay`, `--replay-transcripts`) and `--suggest` run nothing and write no policy.

**Assurance levels** (`internal/assurance`): `STRONG` / `GUARDED` / `BEST_EFFORT` are derived strictly from operator-controlled `runtime.deployment_mode` + `runtime.strong_guarantee` and propagate into explain/audit output only. They never alter policy decisions. `nomos doctor` uses conservative proxy checks (container sandbox, mTLS, OIDC workload identity, durable audit sink, deployment-bound environment) and fails closed when signals are absent.

**Config path resolution**: filesystem-backed fields in config (policy bundles, workspace roots, approval store, TLS files, OIDC public keys, sqlite audit sinks) resolve relative to the **config file directory**, not the process CWD. Absolute paths still win.

**Upstream routes** (`upstream.routes`) act as a fail-closed transport allowlist for `net.http_request` when configured. They constrain host/path/method **before** execution but do not participate in policy authorization — deny-wins remains the only authorization source.

**HTTP `/run`** maps to the same strict action handler as `/action` — there is no parallel execution path. Keep it that way when adding endpoints.

**MCP stdout is protocol-pure**: operator UX (ready banner, logs, errors) goes to stderr; MCP runtime uses a non-emitting in-process audit recorder so stdout carries only MCP protocol frames.

## Package map

- `cmd/nomos` — CLI entrypoint (commands: `doctor`, `policy test|explain`, `mcp`, `serve`, `version`, …)
- `internal/policy` — bundle loading, matching, deny-wins evaluation, explain, bundle lint
- `internal/agenthook` — Claude Code and Codex hooks: shell parser, action mapping, replay, suggest, installers
- `internal/launcher` — embedded default profiles and the coding-agent launcher (`nomos run`)
- `internal/permissiontest` — `nomos test` permission suites
- `internal/service`, `internal/gateway` — HTTP boundary + shared action handler
- `internal/mcp` — MCP server and upstream MCP gateway (stdio newline-delimited JSON, framed responses accepted for compat)
- `internal/normalize`, `internal/action`, `internal/canonicaljson` — determinism layer
- `internal/executor`, `internal/sandbox` — execution + obligation-driven isolation
- `internal/credentials` — lease broker
- `internal/redact`, `internal/audit`, `internal/telemetry` — output guardrails and evidence
- `internal/approval` — fingerprint-bound approvals
- `internal/assurance`, `internal/doctor` — deployment guarantee modeling + preflight
- `internal/bypasssuite`, `internal/owaspmapping`, `internal/supplychain` — standards/bypass verification
- `pkg/sdk` — public Go SDK for HTTP integrations
- `examples/` — configs, policies, quickstart actions (used by smoke tests — keep working)
- `profiles/` — default profiles; embedded copies in `internal/launcher/embedded_profiles`, pinned hashes in `testdata/policy-profiles/hashes.json`
- `testdata/` — checked-in fixtures; prefer relative paths. `testdata/realworld/` holds the 1,526-command corpus and its decision golden

## Conventions to preserve

- **Fail closed** on policy/config errors. Never introduce permissive fallbacks.
- **Reject unknown fields** on typed decoders unless the API explicitly supports extensions.
- Use **stable, descriptive rule IDs** in policy bundles.
- Never accept identity or environment from the agent/action body.
- Never log raw secrets or return them to agents; broker via lease IDs.
- Redact before any output leaves Nomos.
- Keep example configs and quickstart commands green — they are smoke-tested by CI and documented in README.
- Hooks never allow what they cannot parse: unsupported shell syntax asks, or denies with `--on-unsupported deny`.
- A profile change needs re-pinned hashes and a regenerated corpus golden, with every moved decision reviewed in the diff.
- Merge titles drive releases: `feat:` cuts a minor release and `fix:` a patch; `docs:` and `chore:` do not release.
