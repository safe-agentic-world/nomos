# Claude Code Hook

`nomos hook claude-code` is a Claude Code `PreToolUse` hook. Claude Code
runs it before every native `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, and `WebFetch` call (and, if you opt in, every MCP tool
call). The hook maps the call to Nomos actions, evaluates them with the
same deny-wins engine that backs `nomos test`, and answers with the hook
JSON Claude Code expects: `allow`, `deny`, or `ask`.

Why a hook: those native tools never pass through an MCP server, so the
`nomos run claude` launcher cannot see them. Claude Code's own
documentation states that a hook `deny` "blocks the tool even in
`bypassPermissions` mode or with `--dangerously-skip-permissions`" and
that hooks "can tighten restrictions but not loosen them"
([hooks reference](https://code.claude.com/docs/en/hooks)). The same
documentation says a Bash deny rule "isn't a security boundary around the
program" because `/bin/rm`, `bash -c`, and `git -C . push` step around it
([permissions](https://code.claude.com/docs/en/permissions)); the hook
normalizes those spellings before the policy sees them.

## Install

```bash
nomos hook claude-code --install --profile safe-dev
nomos hook claude-code --simulate --profile safe-dev --command "rm -rf tests/ patches/ plan/ ~/"
```

`--install` merges this block into `.claude/settings.json` in the
workspace (or the file given with `--settings`) and leaves every other
setting untouched. Commit the file so the whole team runs the same rules.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "nomos hook claude-code --profile safe-dev",
            "timeout": 10,
            "type": "command"
          }
        ],
        "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch"
      }
    ]
  }
}
```

Use `-p path/to/policy.yaml` instead of `--profile` for your own bundle,
`--print-settings` to see the block without writing it, and `--mcp` to
extend the matcher to `mcp__.*` tools. The `nomos` binary must be on the
`PATH` that Claude Code uses; pass `--hook-command` to register an
absolute path instead.

`--simulate` prints the decision Claude Code would receive, so you can
check a rule set without running the agent:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Nomos: profile safe-dev denies process.exec [\"rm\" \"-rf\" \"tests/\" \"patches/\" \"plan/\" \"~/\"] (rules: safe-dev-deny-catastrophic-delete)"}}
```

## How A Tool Call Becomes A Decision

| Claude Code tool | Nomos action | Resource |
| --- | --- | --- |
| `Bash` / `PowerShell` | one `process.exec` per simple command in the command list | `file://workspace/` with `params.argv` and `params.cwd` |
| `Read` | `fs.read` | `file://workspace/<path relative to the workspace>` |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `fs.write` | same |
| `WebFetch` | `net.http_request` with `params.method: GET` | `url://host/path` |
| `mcp__<server>__<tool>` | `mcp.call` with the tool arguments in `params.tool_arguments` | `mcp://<server>/<tool>` |
| any other tool | no decision; Claude Code's own permission flow applies | |

For `Bash`, the command string is split on `&&`, `||`, `;`, `|`, `&`,
and newlines. Each part is normalized and evaluated on its own, and the
most restrictive result wins across the whole call:

```text
git status && go test ./...      allow  (both parts allowed by safe-dev)
npm test && git push --force     ask    (push requires review)
git status && cat config/.env    deny   (secret-file argument)
```

Normalization before evaluation:

- `/bin/rm`, `/usr/bin/git`, or any path spelling of a command is reduced
  to its base name; the spelling is kept in the audit record.
- `bash -c "..."`, `sh -lc '...'`, `pwsh -Command "..."`, and `cmd /c ...`
  are unwrapped and the inner command list is parsed the same way.
- `env`, `command`, `exec`, `nohup`, `time`, and `nice` prefixes are
  dropped when they carry no options.
- git global options (`-C dir`, `-c key=value`, `--git-dir`,
  `--work-tree`, `--no-pager`, ...) are stripped so `git -C . push` is
  evaluated as `git push`; the directory feeds the workspace check below.
- `cd` changes the effective working directory for the commands that
  follow it and produces no action of its own.

## Decision Semantics

| Policy outcome for any part | Hook answer | Notes |
| --- | --- | --- |
| `DENY` by a rule | `deny` | Cannot be overridden by Claude Code's permission mode or by `allow` rules in settings. |
| `REQUIRE_APPROVAL` | `ask` | Claude Code shows its normal prompt with the Nomos reason. The prompt is the approval; no Nomos approval record is created. |
| `DENY` by default (no rule matched) | `ask`, or `deny` with `--on-default deny` | Use `deny` for unattended `-p` runs, where `ask` cannot be answered. |
| `ALLOW` for every part | `allow` | Skips the prompt. Deny and ask rules in Claude Code settings still apply. |

Two more inputs feed the answer:

- Shell syntax the parser will not interpret yields `ask`, or `deny` with
  `--on-unsupported deny`. This covers variable and command substitution
  (`$HOME`, `$(pwd)`, backticks), heredocs and input redirection,
  redirection to files (only `2>&1`-style descriptor duplication and
  `/dev/null` are accepted), subshells and brace groups, leading
  `VAR=value` assignments, `sudo`/`doas`/`su`, `eval`, `source`,
  `xargs`, `find -exec`/`-delete`, and builtins that change shell state
  (`export`, `trap`, `set`, `pushd`, ...). The reason names the construct
  and the position. The rule is deliberate: when the argv the policy would
  evaluate might differ from what the shell will run, Nomos does not guess.
- A path that resolves outside the workspace root yields `ask`, `deny`
  with `--outside-workspace deny`, or no decision with
  `--outside-workspace passthrough`. This applies to `Read`/`Write`/`Edit`
  paths, `cd` and `git -C` targets, and path-shaped arguments of shell
  commands (`~`, absolute paths, `../`), after symlink resolution of the
  existing part of the path. Only `passthrough` lets Claude Code's own
  flow decide such a call; it never turns into an `allow`.

The workspace root is `--workspace`, else `CLAUDE_PROJECT_DIR`, else the
`cwd` Claude Code sends with the hook input.

Any internal failure, including a policy bundle that does not load or an
audit file that cannot be written, exits with code 2, which Claude Code
treats as a block.

## Audit

Every non-passthrough decision appends one record per evaluated action
(and one per finding) to `.nomos/claude-code-hook.jsonl` under the
workspace, or to `--audit <path>`; `--audit none` disables it. Records
carry the action type, resource, the argv as evaluated, the command
spelling as written, the policy decision and reason code, the matched
rule IDs, the policy bundle hash, the Claude Code permission mode, and the
hook answer. Each line is redacted field by field, then hashed together
with the previous line's hash:

```bash
nomos hook claude-code --verify-audit
```

recomputes the whole chain and fails on the first modified, inserted, or
removed record. The chain is integrity-linked, not signed: it detects
tampering after the fact by anyone who does not also rewrite every later
hash, and it does not prove who wrote a record. Add `.nomos/` to
`.gitignore` unless you want the log in version control.

## Test The Policy Before Claude Does

The hook evaluates the same bundle `nomos test` does, so permission
regressions are caught in CI before they reach an agent:

```bash
nomos test --suite examples/incidents/safe-dev.permissions.json --bundle profiles/safe-dev.yaml
nomos hook claude-code --simulate --profile safe-dev --command "git -C .. push --force"
nomos hook claude-code --simulate --profile safe-dev --tool Read --input '{"file_path":".env"}'
```

The [incident regression suites](../examples/incidents/README.md) cover
the documented incident classes for each default profile; copy the
format for your own bundle.

## Limits

- **Claude Code runs the hook, so its rules bound it.** Per the hooks
  reference, "A timed-out `command`, `http`, or `mcp_tool` hook doesn't
  block the tool call", and users can set `disableAllHooks`; organizations
  can restrict which hooks run with managed settings. The hook does no
  network I/O and evaluates in milliseconds; keep the timeout short and
  treat the hook as policy enforcement inside the harness, not as a
  sandbox around it.
- **Argv, not filesystem state.** Rules see normalized tokens. A file
  reached through an unusual spelling, a symlink the workspace check
  cannot resolve, or a program that reads files by its own logic
  (`python script.py`) is decided by the rules that match that command,
  not by what it will touch. Pair the hook with Claude Code's sandbox for
  OS-level containment.
- **Identity is configured, not authenticated.** `--principal`,
  `--agent`, and `--environment` label the records and select rules with
  identity filters; the hook has no caller to verify.
- **`ask` is Claude Code's prompt.** It does not create a pending Nomos
  approval, and a prompt approved in Claude Code is not recorded in a
  Nomos approval store. Use the gateway when you need durable,
  fingerprint-bound approvals.
- **MCP tools are opt-in.** With a default-deny bundle, matching
  `mcp__*` turns every MCP call into a prompt unless the bundle has
  `mcp.call` rules; add `--mcp` only with such rules in place.
- **Scope.** This is a Claude Code integration. Codex and Gemini CLI have
  their own policy mechanisms; `nomos run` still wires the MCP surface for
  both.

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-p`, `--policy-bundle` | | bundle path; mutually exclusive with `--profile` |
| `--profile` | `safe-dev` | embedded profile `safe-dev`, `ci-strict`, or `prod-locked` |
| `--workspace` | `CLAUDE_PROJECT_DIR`, then hook `cwd` | workspace root for file resources and the boundary check |
| `--on-default` | `ask` | `ask` or `deny` when no rule matches |
| `--on-unsupported` | `ask` | `ask` or `deny` for shell syntax the parser refuses |
| `--outside-workspace` | `ask` | `ask`, `deny`, or `passthrough` for paths outside the workspace |
| `--audit` | `.nomos/claude-code-hook.jsonl` | audit file, or `none` |
| `--principal`, `--agent`, `--environment` | `developer`, `claude-code`, `local` | identity recorded on actions |
| `--install`, `--settings`, `--matcher`, `--mcp`, `--timeout`, `--hook-command` | | register the hook in a settings file |
| `--print-settings` | | print the settings block instead of writing it |
| `--simulate`, `--tool`, `--input`, `--command` | | evaluate a synthetic call and print the decision |
| `--verify-audit` | | verify the audit chain and exit |
