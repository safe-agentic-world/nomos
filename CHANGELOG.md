# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and semantic versioning.

## [Unreleased]

### Added

- `nomos hook codex`: a Codex `PreToolUse` and `PermissionRequest` hook
  that decides `Bash` commands and `apply_patch` files with the same
  parser, profiles, and audit as the Claude Code hook. A deny is returned
  where Codex can act on it; an ask leaves Codex's own prompt in place and
  becomes a deny when approvals are disabled. `--install` writes
  `.codex/hooks.json` with only the keys Codex accepts. The contract was
  verified from the Codex source at a pinned commit; a live end-to-end run
  is still pending. See `docs/codex-hook.md`.
- `nomos hook claude-code --replay <file>` and `--replay-transcripts`: replay
  recorded tool calls (a corpus JSONL, hook input JSON, Claude Code
  transcript lines, or plain commands) through a profile or bundle and
  report the allow, deny, and ask counts, why calls ask, the programs that
  ask most, and every deny with its reason. Replay writes no audit and runs
  nothing.
- `scripts/e2e-claude-code-hook/`: a re-runnable end-to-end validation of
  the hook against headless Claude Code sessions in throwaway projects with
  canary files, and the resulting record in
  `docs/validation-claude-code-hook.md`.
- Issue templates for bypass reports and noisy decisions, and a roadmap
  built on the verified incident research.
- A real-world command corpus (`testdata/realworld/`, 1,526 build and test
  commands from ten permissively licensed repositories) with a decision
  golden that fails when a profile change denies a benign command or frees
  a dangerous one.
- Backslash escapes in argv patterns (`'~/\*'` matches the literal glob).

### Changed

- Default profiles: the catastrophic-delete rules now match the home
  directory, filesystem root, drive roots, and parent directory as a whole
  or as a literal glob, instead of every absolute path; other deletes
  outside the workspace are asked about by the hook's boundary check.
  `safe-dev` asks before any `rm` inside the workspace and before writing
  a secrets file, and allows the everyday git workflow, the project
  toolchain (Go, Rust, Node, Python, Make, and friends), workspace file
  operations, and more read-only git and inspection commands; `ci-strict`
  gains conservative file operations and denies secret-file writes. On the
  corpus, `safe-dev` allows went from 157 to 578 of 1,526 commands and
  denies from 13 to 2, with every incident case still denied or reviewed.
- A bare `env` is treated as the read-only command it is, not as a wrapper.
- The shell parser now maps file redirections (`> out.txt`, `>> log`,
  `2> err`, `&> all`, `< input`) to `fs.write` and `fs.read` actions the
  policy decides, instead of refusing them, and accepts simple parameter
  expansions (`$NAME`, `${NAME}`, `$?`) in the arguments of print-only
  commands (`echo`, `printf`, `printenv`, `test`, `true`). Expansions
  anywhere else, command substitution, heredocs, and redirection targets
  that carry a quote or an expansion are still refused. On the corpus this
  moved `safe-dev` from 578 to 675 allows.

## [0.14.0] - 2026-09-26

### Added

- `nomos hook claude-code`: a Claude Code `PreToolUse` hook that decides the
  agent's native `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`,
  and `WebFetch` calls (and, opt-in, MCP tools) with a Nomos bundle or
  embedded profile. Shell commands are split into simple commands and each
  is evaluated; `deny` rules produce a hook `deny`, which Claude Code
  enforces in every permission mode including `bypassPermissions`;
  `REQUIRE_APPROVAL` produces `ask`; unmatched actions ask by default
  (`--on-default deny` for unattended runs). Syntax the parser will not
  interpret (variable or command substitution, heredocs, redirection to
  files, subshells, `sudo`, `eval`, `xargs`, state-changing builtins, git
  configuration overrides such as `-c core.pager=...`) and paths that
  resolve outside the workspace, checked in option values and embedded
  assignments too, from every working directory a command could run in
  after a failed `cd`, and with symlinks resolved before a following `..`,
  are never auto-allowed. Includes
  `--install` (merges into `.claude/settings.json`), `--print-settings`,
  `--simulate`, and `--verify-audit`. See `docs/claude-code-hook.md`.
- Hash-chained JSONL audit recorder (`audit.NewFileChainRecorder`) for
  short-lived processes: each line is redacted field by field, hashed after
  redaction, and linked to the previous line, and `audit.VerifyFileChain`
  re-verifies the file. The hook writes to `.nomos/claude-code-hook.jsonl`
  by default.
- Wildcard tokens in `exec_match.argv_patterns`: a token containing `*` or
  `?` matches a whole argv token (`*` also matches `/`), so a rule such as
  `["**", "*.pem", "**"]` denies a secret path in any argument position.
- Incident regression suites under `examples/incidents/` for the three
  default profiles, run by `go test ./...` and CI.

### Changed

- Default profiles now deny commands whose arguments name secret material
  (`.env` and variants, `.pem`, `.key`, SSH keys, `.aws`, `.gcp`, `.kube`,
  kubeconfig, `.netrc`), deny `rm`/`rmdir` targeting the home directory,
  the filesystem root, any absolute path, or a parent directory, and gate
  destructive git operations however their arguments are spelled
  (`git reset --hard HEAD~5`, `git clean -fdx`, `git push --force ...`).
  `safe-dev` additionally allows common read-only inspection tools (`cat`,
  `head`, `grep`, `find`, ...) so they stop prompting. Profile hashes in
  `testdata/policy-profiles/hashes.json` were re-pinned.
- Documentation corrections: the launcher is described as the MCP boundary
  for a launched session rather than "the default execution boundary";
  `AGENTS.md` no longer references directories that do not exist; the MCP
  compatibility note explains how forwarded tool lists can change; the
  policy language reference documents exact-length argv matching.

### Developer Workflow

- Pinned build/CI toolchains to patched Go 1.26.8 after the installed
  Go 1.26.0 standard library was flagged by `govulncheck`. The Go language
  baseline remains 1.25; automatic toolchain selection downloads the pin.

- Added `nomos test --suite ... --bundle ...` for offline permission
  regressions, text/JSON output, and CI exit codes.
- Added an installable Python SDK, optional real LangGraph adapter, and
  account-free local inbox integration with durable SQLite delivery.
  Package installation is from this checkout; no PyPI release is claimed.
- Remote approval decisions now require an authenticated principal in
  `approvals.approver_principals`; empty lists authorize nobody. Configure
  a separate reviewer before upgrading existing approval workflows.
- Approval webhooks are disabled unless their specific token is configured.
- Authorization decision audit failures now stop service processing;
  failed external-report writes return an error instead of `recorded: true`.
- Local callback guards reject built-in actions and require explicit
  `external_authorized` mode. Migrate built-ins to direct client calls,
  or use a custom action with its own policy for local tool execution.
- Removed the standalone `nomos job run` runner, its CI examples/workflow,
  misleading callback examples, and broad enterprise deployment guides.
  No Kubernetes manifests or Helm charts were present to remove.
- Refocused README, quickstart, contribution guidance, and CI on one
  usable custom-tool workflow. Existing MCP/launcher APIs remain compatible.

Earlier entries below describe the project's previous development history;
the focused workflow and migration notes above supersede removed surfaces.

### Security

- agent launcher now passes `--mcp-config <generated>` to `claude` so the launched Claude Code session is actually governed by Nomos. Previously the launcher set `CLAUDE_MCP_CONFIG` and `CODEX_MCP_CONFIG` environment variables that neither CLI honors, producing sessions that printed `Nomos workspace active` and recorded `default_boundary: true` in the audit log without any MCP server attached. The launcher now records `mcp_wiring_method` (`mcp_config_flag` for Claude, `operator_managed` for Codex) and the resolved `agent_launch_argv`, drops the un-verifiable `default_boundary` claim, and prints a `Verify after launch` block instructing operators to confirm `nomos` shows in `/mcp` before trusting the session.
- agent launcher default profiles now have a single public canonical source under `profiles/`. The embedded launcher copies are generated from that source by `make pin-profile-hashes`, and `testdata/policy-profiles/hashes.json` is the authoritative checked-in hash pin file.
- agent launcher now embeds the three default profile bundles (`safe-dev`, `ci-strict`, `prod-locked`) into the binary and materializes them to `~/.nomos/profiles/<name>.yaml` on demand. Previously the launcher only resolved profiles via `<workspaceRoot>/profiles/` or the calling process's git root, so `nomos run` failed closed for every enterprise install path (Homebrew, Scoop, installer script, `go install`) when run from any project directory that was not a checkout of the nomos source repo. The new `Bundle source:` line in the launcher summary and the `profile_source` audit field disclose which tier (`workspace`, `repo`, or `embedded`) was used.
- MCP `tools/list` now advertises any direct governed tool (`read_file`, `write_file`, `apply_patch`, `run_command`, `http_request` and the canonical `nomos.*` aliases) whose action_type has at least one matching `ALLOW` or `REQUIRE_APPROVAL` rule for the calling identity, replacing the prior synthetic-probe approach that hid governed tools whenever the placeholder probe (e.g. `argv=["echo","sample"]` for exec, `url://example.com/status` for HTTP) hit a default-deny rule under realistic profiles like `safe-dev`. Under the previous behavior, an agent running with `nomos run claude --profile safe-dev` saw only `read_file`, `write_file`, `apply_patch`, and `nomos_capabilities` in its tool list — `run_command` and `http_request` silently disappeared and the agent escaped to native shell to perform governed actions, defeating M63's "Nomos becomes the default execution boundary" promise. The new rule-based capability scan in `internal/mcp/tool_discovery.go` decides direct-tool visibility from action_type + identity only (ignoring resource pattern, params, and exec_match), establishing M63 precedence over M31's resource-aware probe-based hiding for direct tools. Resource-aware hiding still applies to upstream MCP fanout (`mcp.call`) where each forwarded tool maps to a distinct `mcp://` resource. External-policy backend health is still fail-closed: if a configured external policy (e.g. an unreachable OPA) returns `deny_by_external_policy_error` on the discovery probe, the tool is hidden regardless of local capability scan.

### Added

- strong-guarantee deployment guidance and conservative readiness checks (`runtime.strong_guarantee`)
- deterministic `assurance_level` derivation in audit and `nomos policy explain`
- `assurance_level` and `mediation_notice` in `nomos.capabilities`
- normalization corpus, redirect controls, and bypass-suite validation coverage
- corpus-backed redaction harness and secret no-leak integration coverage
- actionable `policy explain` denial context and remediation hints
- workflow-managed release publishing with multi-arch archives, checksums, Homebrew tap updates, and Scoop manifest updates
- `safe` starter policy bundle for safer local file mediation defaults
- default workspace profiles `safe-dev`, `ci-strict`, and `prod-locked`; current hashes are pinned in `testdata/policy-profiles/hashes.json`
- `nomos profiles list|show|verify` for inspecting the default profiles embedded in the running binary

### Changed

- MCP runtime output isolation to keep stdout protocol-safe
- MCP tool-call adapter compatibility for current Claude Code wrapper shapes (`input` and extra wrapper metadata)
- MCP file-tool error mapping now distinguishes `normalization_error`, `not_found`, and `execution_error`
- release build metadata injection support for `Version`, `Commit`, `BuildDate`
- release assets now publish archives (`.tar.gz` / `.zip`) instead of raw binaries
- install guidance now centers on `go install`, GitHub Releases, Homebrew tap, Scoop, and the provided installer script
