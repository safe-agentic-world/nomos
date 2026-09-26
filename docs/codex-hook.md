# Codex Hook

`nomos hook codex` decides Codex's shell commands and file patches with a
Nomos policy through Codex's lifecycle hooks: `PreToolUse`, which can block
a tool call, and `PermissionRequest`, which can answer an approval before
Codex's own reviewer or the user sees it. It shares the parser, the decision
pipeline, the profiles, and the audit format of the
[Claude Code hook](claude-code-hook.md).

The contract below was verified from the Codex source
(`codex-rs/hooks`, `codex-rs/core/src/hook_runtime.rs`,
`codex-rs/core/src/exec_policy.rs`, `codex-rs/apply-patch`, and the
generated schemas under `codex-rs/hooks/schema/generated/`) at commit
`e72da2b5` of `openai/codex` on 2026-09-26, where the hooks feature is on
by default, and then reviewed adversarially against that source. It has
not yet been exercised against a live Codex binary the way the Claude Code
hook was ([validation record](validation-claude-code-hook.md)); that run
is the next step for this adapter.

## Install

```bash
nomos hook codex --install --profile safe-dev
nomos hook codex --simulate --profile safe-dev --command "rm -rf ~/"
nomos hook codex --simulate --profile safe-dev --command "git push origin main"
```

`--install` merges two entries into the project's `.codex/hooks.json`
(`--hooks-file ~/.codex/hooks.json` for a user-wide registration): a
`PreToolUse` hook and a `PermissionRequest` hook, both matching
`Bash|apply_patch|Write|Edit` (`Write` and `Edit` are the aliases Codex
accepts for `apply_patch`), with a 10 second timeout. Only the keys Codex
accepts are written, because its parser rejects unknown fields, and a file
that Codex would refuse (an unknown top-level key or event name) is left
untouched with an error, because Codex drops such a file entirely and the
hook would silently never run. Codex runs the command through the login
shell, so generated arguments are quoted. Codex loads project hooks only in
trusted projects and asks you to trust each hook by its content the first
time it starts; accept the Nomos entry to activate it. `--mcp` extends the
matcher to `^(Bash|apply_patch|Write|Edit|mcp__.*)$` (anchored, because a
matcher with regular-expression characters is otherwise matched anywhere in
the tool name); `--permission-request=false` registers only the blocking
hook.

## How A Tool Call Becomes A Decision

| Codex tool | Nomos action | Notes |
|---|---|---|
| `Bash` (`tool_input.command`) | `process.exec` per simple command | the same shell parser as the Claude Code hook: wrappers unwrapped, refused syntax never auto-allowed, paths checked from every possible working directory |
| `apply_patch` (`tool_input.command` is the patch text) | `fs.write` per file in `*** Add File`, `*** Update File`, `*** Move to`, and `*** Delete File` headers | headers are matched the way Codex's parser matches them (whitespace trimmed outside update hunks); a patch without file headers, with an unrecognized `***` marker, or with a `Move to` outside an update hunk is refused, not allowed |
| `mcp__<server>__<tool>` | `mcp.call` on `mcp://server/tool` | only when installed with `--mcp` |
| any other tool (`spawn_agent`, ...) | none | passthrough: Nomos prints nothing |

A patch is decided as a whole. With `--outside-workspace passthrough`, a
patch that touches a workspace file and a file outside it is left to Codex
entirely; the allowed part never decides the call alone, and a denied part
still denies it.

## Decision Semantics

Codex's `PreToolUse` hook can block but cannot ask: the output
`permissionDecision: "ask"` and a bare `"allow"` are rejected as
unsupported and leave the hook without effect. `PermissionRequest` runs
only when Codex is about to ask someone, and it carries more than plain
confirmations (see below). Nomos therefore expresses each decision only
where Codex acts on it as intended:

| Nomos decision | `PreToolUse` | `PermissionRequest` |
|---|---|---|
| `deny` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":...}}`; Codex tells the model the command was blocked | `decision: {"behavior":"deny"}` |
| `allow` | no output; Codex's normal flow continues | no output by default; with `--permission-request-allow`, `decision: {"behavior":"allow"}` for a plain request in `default` mode, so the prompt is skipped |
| `ask` | a `deny` whose reason says confirmation was required and cannot be requested here; `--ask passthrough` prints nothing instead | no output: Codex's reviewer or the user decides |
| passthrough | no output | no output |

Any internal failure (unreadable input, a policy that fails to load, an
audit write error) exits 2 with the reason on stderr, which Codex treats as
a block for `PreToolUse`. A lifecycle event that carries no tool call
(`PostToolUse`, for example, if the command is registered there) is
ignored: nothing is evaluated, audited, or printed.

### Why an ask is a deny

`permission_mode` in the hook input is `bypassPermissions` only when
approvals are disabled (`--dangerously-bypass-approvals-and-sandbox`);
every other approval policy reports `default`, including Codex's usual
on-request policy. In on-request mode with the normal sandbox, a command
the hook does not block runs inside the sandbox without a prompt: Codex
prompts only in untrusted mode, for an escalation the model requests, for
a retry after a sandbox denial, or for a command Codex itself classes as
dangerous. So a Nomos `ask` cannot rely on a Codex prompt. It becomes a
`deny` by default in both modes, with a reason the model can act on
(`git push` asks under `safe-dev`, so the model is told to leave the push
to you). `--ask passthrough` makes an ask silent instead, which in
on-request mode means a sandboxed run with no human in the loop; use it
only where Codex's own policy already prompts.

### Escalations and the automated reviewer

`PermissionRequest` is also how Codex asks about escalations: a retry
outside the sandbox after a denial, a network grant (`description:
"network-access <host>"`), or a command the model marked
`with_escalated_permissions` with a `justification`. An `allow` there
removes a protection rather than a prompt, so Nomos never answers `allow`
to a request that carries anything beyond the plain tool input, even with
`--permission-request-allow`. It also never answers `allow` with approvals
disabled, where the request may come from Codex's strict automated review
rather than from a user prompt: silence leaves that reviewer in charge. A
Nomos `deny` is answered in every case.

For unattended runs combine `--on-default deny` with the default
`--ask deny` so that nothing the policy has not allowed can run.

## Audit

Every decision is appended to `.nomos/codex-hook.jsonl` in the workspace as
a redacted, hash-chained record with the event (`PreToolUse` or
`PermissionRequest`), the normalized action, the matched rules, the
permission Nomos computed (`hook_permission`), and what Codex actually
received (`wire_decision`: `deny`, `allow`, or `none`), together with the
adapter settings that shaped it (`ask_mode`, `permission_request_allow`,
`outside_workspace`) and Codex's `turn_id`. `PermissionRequest` inputs
carry no `tool_use_id`, so their action ids derive from the turn id and a
hash of the request, which keeps two requests in one turn distinct.
`nomos hook codex --verify-audit` re-checks the chain. `--audit none`
disables the log; `--audit <path>` moves it.

## Limits

- **Not yet validated against a live Codex.** The input and output shapes,
  the matcher semantics, and the mode behavior are taken from the Codex
  source at the pinned commit; behavior in released Codex builds may
  differ until an end-to-end run like the Claude Code one is recorded.
- **A hook is bounded by the harness.** Codex treats a hook that times out
  or crashes as failed and does not block; `async` hooks cannot block; an
  organization can restrict hooks to managed ones. Keep the timeout short
  and the hook local, and treat it as policy enforcement inside Codex, not
  as a sandbox around it.
- **The working directory is the session's.** Codex's shell tool accepts a
  `workdir` (and a `shell`, an `environment_id`, and sandbox flags) that
  the hook input does not include; the hook sees only the command and the
  session `cwd`. A relative path in a command started from another
  working directory is judged against the session directory. Prefer
  absolute paths in policies that must hold regardless.
- **Input to a running process is invisible.** Codex can write to the stdin
  of a process it started (`write_stdin`) without a `PreToolUse` event, so
  an interactive interpreter or shell is an unhooked channel once it is
  running. The default profiles therefore ask (`safe-dev`) or deny
  (`ci-strict`, `prod-locked`) before a bare `python`, `node`, `ruby`,
  `bash`, `sh`, and the other interpreters and shells, and before inline
  code (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`,
  `deno eval`). Scripts started by name (`python build.py`) are decided by
  the toolchain rules, and flag clusters or glued forms (`-Bc`, `-c'code'`)
  are not recognized: an interpreter that may run is an interpreter that
  may run anything.
- **`apply_patch` reveals paths, not effects.** The policy sees which files
  a patch touches. What the new content does when it runs is decided by
  the rules that allow running it. Header paths are trimmed, so a path
  Codex would keep with a leading space is judged by its trimmed form,
  which is never looser; `~` is not expanded by Codex and is treated by
  Nomos as the home directory, which is outside the workspace.
- The shell parser's limits from the [Claude Code hook guide](claude-code-hook.md#limits)
  apply unchanged.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `--policy-bundle` | | policy bundle (YAML or JSON); mutually exclusive with `--profile` |
| `--profile` | `safe-dev` | embedded profile `safe-dev`, `ci-strict`, or `prod-locked` |
| `--workspace` | hook `cwd` | workspace root for file resources and the boundary check; `CLAUDE_PROJECT_DIR` is never consulted, because Codex replays the environment it was started from into its hooks |
| `--on-default` | `ask` | `ask` or `deny` when no rule matches |
| `--on-unsupported` | `ask` | `ask` or `deny` for shell syntax the parser refuses |
| `--outside-workspace` | `ask` | `ask`, `deny`, or `passthrough` for paths outside the workspace |
| `--ask` | `deny` | what an `ask` becomes in `PreToolUse`, which cannot ask: `deny` or `passthrough` |
| `--permission-request-allow` | off | answer a plain `PermissionRequest` with `allow`; never for escalations, never with approvals disabled |
| `--audit` | `.nomos/codex-hook.jsonl` | audit file, or `none` |
| `--principal`, `--agent`, `--environment` | `developer`, `codex`, `local` | identity recorded on actions |
| `--install`, `--hooks-file`, `--matcher`, `--mcp`, `--timeout`, `--hook-command`, `--permission-request` | | register the hook in a `hooks.json` file |
| `--print-hooks` | | print the `hooks.json` document instead of writing it |
| `--simulate`, `--tool`, `--input`, `--command`, `--event`, `--permission-mode` | | evaluate a synthetic call and print the decision and what Codex would do with it; `--event` is `PreToolUse` or `PermissionRequest`, `--permission-mode` is `default` or `bypassPermissions` |
| `--verify-audit` | | verify the audit chain and exit |
