# Roadmap

Nomos exists so that a coding agent's irreversible actions pass a
deterministic, testable decision before they run. This roadmap is ordered by
what the [verified incident research](../README.md#why-nomos) says users are
missing, not by what is easiest to build. Each milestone ships as a pull
request with CI and a release, and each names how it is verified.

## Principles

- **Fail closed.** A command Nomos cannot interpret, or a path it cannot
  place inside the workspace, is never auto-allowed.
- **No silent policy changes.** Suggested rules are printed for a human to
  review and commit; nothing edits a policy behind the user's back.
- **Claims are tested.** A capability is documented only after a test,
  a smoke check, or a recorded validation run exercises it.
- **Local by default.** The hook reads and writes only inside the project
  and its audit file, does no network I/O, and sends nothing anywhere.
- **Honest limits.** Every guide states what the feature does not cover.
  Nomos is not a sandbox, a prompt-injection detector, or a backup.

## Milestones

### 1. Real-world noise measurement (delivered in v0.15.0)

A hook that prompts on every second command recreates the approval fatigue
it exists to remove. Ship a replay mode that runs a corpus of real developer
commands (build and test steps from permissively licensed open-source
projects, plus a user's own Claude Code transcripts) through a profile and
reports how many would allow, deny, or ask, and why.

Verified by: a checked-in corpus with source attribution, a regression test
that fails when a benign build command is denied or an incident case stops
denying, and the ask rate reported in the release notes.

### 2. Nag-free defaults (delivered in v0.15.0 and v0.16.0)

Record which asked commands the user then approved, and let
`nomos hook claude-code --suggest` propose allow rules from that record.
Tune the `safe-dev` profile with the corpus so ordinary build, test, lint,
and read-only git commands do not prompt inside the workspace, while every
incident case still denies or asks.

Verified by: the corpus ask rate for `safe-dev` and the incident suites in
CI; suggestions are never applied automatically.

### 3. End-to-end runs with a real agent (delivered in v0.15.0)

Run Claude Code headless in throwaway projects with the hook installed,
under default and bypass permission modes, and drive it toward the
commands from the incident reports. Publish the decisions and the agent's
own permission denials as a validation record.

Verified by: a checked-in record with the exact prompts, hook decisions,
and audit lines; re-runnable with a script.

### 4. A second harness (delivered in v0.16.0; live run pending)

Adapt the same parser and decision pipeline to the next coding agent that
exposes a blocking pre-tool hook, chosen from primary-source verification of
its hook contract (input fields, output that blocks, behavior in auto
modes). Codex was chosen: its hooks are Claude-shaped, on by default, and
fire with approvals disabled. `nomos hook codex` ships with the contract
verified from source and an adversarial review against that source closed
on the same release; the live end-to-end run against a Codex binary is
next and the guide says so.

Verified by: contract tests against the harness's documented input and
output, plus an adversarial review like the one the Claude Code hook had.

### 5. Trust holes named by the research (next)

- Pin upstream MCP tool definitions (name, description, input schema) and
  require re-approval when one changes, so a class approval cannot survive a
  description rewrite.
- Replace the executor's blanket rejection of `--` arguments with flag
  patterns expressed in policy.

Verified by: unit tests for the pin and the change detection, an
`explain` reason for the new deny, and updated policy docs.

### 6. Distribution and community (in progress)

Lead the README, the repository description, and the release notes with the
hook; keep the incident corpus open to contributions through the bypass and
noisy-decision issue templates; answer every issue and discussion.

Verified by: templates in `.github/ISSUE_TEMPLATE`, a Discussions
announcement per release, and the contribution paths in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Not planned

Hosted accounts, billing, cluster manifests, Helm packaging, infrastructure
orchestration, telemetry that leaves the machine, and a standalone
coding-agent job platform. MCP and launcher interfaces remain supported as
routes into the same decision pipeline.

## Status

Delivered so far: the `nomos test` permission suites, the Python SDK and
LangGraph adapter, the local inbox example, the MCP server and HTTP gateway,
in v0.14.0 the Claude Code hook with the incident regression suites, in
v0.15.0 the real-world corpus with its decision golden, replay mode, the
end-to-end validation record, and the first profile tuning, and in v0.16.0
the Codex hook, the `PostToolUse` record with `--suggest`, redirection and
expansion handling in the parser, and the interpreter rules. Adoption is an
outcome to measure with users, not a claim to make in advance.
