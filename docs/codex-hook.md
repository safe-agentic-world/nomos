# Codex Hook

`nomos hook codex` decides Codex's shell commands and file patches with a
Nomos policy through Codex's lifecycle hooks: `PreToolUse`, which can block
a tool call, and `PermissionRequest`, which can answer an approval before
Codex shows its prompt. It shares the parser, the decision pipeline, the
profiles, and the audit format of the [Claude Code hook](claude-code-hook.md).

The contract below was verified from the Codex source
(`codex-rs/hooks`, `codex-rs/core/src/hook_runtime.rs`, and the generated
schemas under `codex-rs/hooks/schema/generated/`) at commit `e72da2b5`
of `openai/codex` on 2026-09-26, where the hooks feature is on by default.
It has not yet been exercised against a live Codex binary the way the
Claude Code hook was ([validation record](validation-claude-code-hook.md));
that run is the next step for this adapter.

## Install

```bash
nomos hook codex --install --profile safe-dev
nomos hook codex --simulate --profile safe-dev --command "rm -rf ~/"
```

`--install` merges two entries into the project's `.codex/hooks.json`
(`--hooks-file ~/.codex/hooks.json` for a user-wide registration): a
`PreToolUse` hook and a `PermissionRequest` hook, both matching
`Bash|apply_patch|Write|Edit`, with a 10 second timeout. Only the keys Codex
accepts are written, because its parser rejects unknown fields. Codex loads
project hooks only in trusted projects and asks you to trust each hook by
its content the first time it starts; accept the Nomos entry to activate
it. `--mcp` extends the matcher to `mcp__*` tools; `--permission-request=false`
registers only the blocking hook.

## How A Tool Call Becomes A Decision

| Codex tool | Nomos action | Notes |
|---|---|---|
| `Bash` (`tool_input.command`) | `process.exec` per simple command | the same shell parser as the Claude Code hook: wrappers unwrapped, refused syntax never auto-allowed, paths checked from every possible working directory |
| `apply_patch` (`tool_input.command` is the patch text) | `fs.write` per file in `*** Add File`, `*** Update File`, `*** Move to`, and `*** Delete File` headers | a patch without file headers is refused, not allowed |
| `mcp__<server>__<tool>` | `mcp.call` on `mcp://server/tool` | only when installed with `--mcp` |
| any other tool (`spawn_agent`, ...) | none | passthrough: Nomos prints nothing |

## Decision Semantics

Codex's `PreToolUse` hook can block but cannot ask: the output
`permissionDecision: "ask"` and a bare `"allow"` are rejected as unsupported
and leave the hook without effect. Nomos therefore expresses each decision
where Codex can act on it:

| Nomos decision | `PreToolUse` | `PermissionRequest` |
|---|---|---|
| `deny` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":...}}`; Codex tells the model the command was blocked | `decision: {"behavior":"deny"}` |
| `allow` | no output; Codex's normal flow continues | `decision: {"behavior":"allow"}`, so the prompt is skipped |
| `ask` | no output in `default` mode, so Codex prompts as usual; in `bypassPermissions` mode (approvals disabled) nothing can ask, so it becomes a `deny` unless `--ask-in-bypass passthrough` | no output: the user decides |
| passthrough | no output | no output |

Any internal failure (unreadable input, a policy that fails to load, an
audit write error) exits 2 with the reason on stderr, which Codex treats as
a block for `PreToolUse`.

`PermissionRequest` runs only when Codex would ask, so it never fires with
approvals disabled; in that mode the only enforcement is the `PreToolUse`
deny, which is why an `ask` there defaults to a deny. For unattended runs
combine `--on-default deny` with the default `--ask-in-bypass deny` so that
nothing the policy has not allowed can run.

## Audit

Every decision is appended to `.nomos/codex-hook.jsonl` in the workspace as
a redacted, hash-chained record with the event (`PreToolUse` or
`PermissionRequest`), the normalized action, the matched rules, and the
permission returned. `nomos hook codex --verify-audit` re-checks the chain.
`--audit none` disables the log; `--audit <path>` moves it.

## Limits

- **Not yet validated against a live Codex.** The input and output shapes,
  the matcher aliases, and the bypass-mode behavior are taken from the
  Codex source at the pinned commit; behavior in released Codex builds may
  differ until an end-to-end run like the Claude Code one is recorded.
- **A hook is bounded by the harness.** Codex treats a hook that times out
  or crashes as failed and does not block; `async` hooks cannot block; an
  organization can restrict hooks to managed ones. Keep the timeout short
  and the hook local, and treat it as policy enforcement inside Codex, not
  as a sandbox around it.
- **`apply_patch` reveals paths, not effects.** The policy sees which files
  a patch touches. What the new content does when it runs is decided by
  the rules that allow running it.
- The shell parser's limits from the [Claude Code hook guide](claude-code-hook.md#limits)
  apply unchanged.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `--policy-bundle` | | policy bundle (YAML or JSON); mutually exclusive with `--profile` |
| `--profile` | `safe-dev` | embedded profile `safe-dev`, `ci-strict`, or `prod-locked` |
| `--workspace` | hook `cwd` | workspace root for file resources and the boundary check |
| `--on-default` | `ask` | `ask` or `deny` when no rule matches |
| `--on-unsupported` | `ask` | `ask` or `deny` for shell syntax the parser refuses |
| `--outside-workspace` | `ask` | `ask`, `deny`, or `passthrough` for paths outside the workspace |
| `--ask-in-bypass` | `deny` | what an `ask` becomes when `permission_mode` is `bypassPermissions`: `deny` or `passthrough` |
| `--audit` | `.nomos/codex-hook.jsonl` | audit file, or `none` |
| `--principal`, `--agent`, `--environment` | `developer`, `codex`, `local` | identity recorded on actions |
| `--install`, `--hooks-file`, `--matcher`, `--mcp`, `--timeout`, `--hook-command`, `--permission-request` | | register the hook in a `hooks.json` file |
| `--print-hooks` | | print the `hooks.json` document instead of writing it |
| `--simulate`, `--tool`, `--input`, `--command`, `--event`, `--permission-mode` | | evaluate a synthetic call and print the decision and what Codex would receive |
| `--verify-audit` | | verify the audit chain and exit |
