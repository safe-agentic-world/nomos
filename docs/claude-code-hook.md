# Claude Code Hook

`nomos hook claude-code` is a Claude Code `PreToolUse` hook. Claude Code
runs it before every native `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, and `WebFetch` call (and, if you opt in, every MCP tool
call). The hook maps the call to Nomos actions, evaluates them with the
same deny-wins engine that backs `nomos test`, and answers with the hook
JSON Claude Code expects: `allow`, `deny`, or `ask`.

Why a hook: those native tools never pass through an MCP server, so the
`nomos run claude` launcher cannot see them. Claude Code's documentation
says that "PreToolUse hooks run before every tool call, whether or not it
needs permission" ([hooks reference](https://code.claude.com/docs/en/hooks))
and that "a blocking hook also takes precedence over allow rules" and
"stops the tool call before permission rules are evaluated"
([permissions](https://code.claude.com/docs/en/permissions)). The
[validation record](validation-claude-code-hook.md) shows this holding
in practice: under `--dangerously-skip-permissions`, a hook `ask` or
`deny` ended in Claude Code refusing the call. The same documentation
says a Bash deny rule "isn't a security boundary around the program"
because `/bin/rm`, `bash -c`, and `git -C . push` step around it; the hook
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
| `Bash` redirection (`> file`, `>> file`, `2> file`, `&> file`, `< file`) | `fs.write` or `fs.read` for the file, attached to the simple command | `file://workspace/<path relative to the workspace>` |
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
- git's harmless global options (`-C dir`, `--no-pager`, `-p`, `--bare`,
  ...) are stripped so `git -C . push` is evaluated as `git push`; the
  `-C` directory feeds the workspace check below. Options that execute
  configured commands or relocate the repository (`-c key=value`,
  `--config-env`, `--exec-path`, `--git-dir`, `--work-tree`,
  `--namespace`) are refused, because `git -c core.pager=... log` or an
  alias override runs whatever the value says.
- `cd` produces no action of its own and changes the working directory
  for what follows. A real shell keeps going after a failed `cd` when the
  separator is `;`, `||`, `|`, or `&`, so the hook tracks every directory
  the next command could run in: after `cd nope ; cat ../secret.txt` the
  read is checked from both the original directory and `nope`, and the
  escape from the original directory is caught. Only `cd sub && ...`
  narrows the next command to `sub`.

## Decision Semantics

| Policy outcome for any part | Hook answer | Notes |
| --- | --- | --- |
| `DENY` by a rule | `deny` | Cannot be overridden by Claude Code's permission mode or by `allow` rules in settings. |
| `REQUIRE_APPROVAL` | `ask` | Claude Code shows its normal prompt with the Nomos reason. The prompt is the approval; no Nomos approval record is created. |
| `DENY` by default (no rule matched) | `ask`, or `deny` with `--on-default deny` | Use `deny` for unattended `-p` runs, where `ask` cannot be answered. |
| `ALLOW` for every part | `allow` | Skips the prompt. Deny and ask rules in Claude Code settings still apply. |

Two more inputs feed the answer:

- Shell syntax the parser will not interpret yields `ask`, or `deny` with
  `--on-unsupported deny`. This covers command substitution (`$(pwd)`,
  backticks), heredocs, process substitution, subshells and brace groups,
  leading `VAR=value` assignments, `sudo`/`doas`/`su`, `eval`, `source`,
  `xargs`, `find -exec`/`-delete`, and builtins that change shell state
  (`export`, `trap`, `set`, `pushd`, ...). A simple parameter expansion
  (`$HOME`, `${NAME}`, `$?`) is kept as literal text and accepted only in
  the arguments of a print-only command (`echo`, `printf`, `printenv`,
  `test`, `true`); anywhere else (`rm -rf $DIR`, `bash -c "echo $X"`, a
  redirection target, the command name itself) it is refused, because the
  value could change what runs or what is touched. A file redirection
  (`> out.txt`, `>> log`, `2> err`, `&> all`, `< input`) is not refused:
  it becomes an `fs.write` or `fs.read` on that file, decided by the
  policy and checked against the workspace boundary like any other path;
  descriptor duplication (`2>&1`), `/dev/null`, and plain here-strings
  stay transparent. The reason names the construct and the position. The
  rule is deliberate: when the argv the policy would evaluate might differ
  from what the shell will run, Nomos does not guess.
- A path that resolves outside the workspace root yields `ask`, `deny`
  with `--outside-workspace deny`, or no decision with
  `--outside-workspace passthrough`. This applies to `Read`/`Write`/`Edit`
  paths, `cd` and `git -C` targets, and path-shaped arguments of shell
  commands (`~`, absolute paths, `../`, names containing a separator),
  including option values in any spelling (`-C /tmp`, `-C/tmp`,
  `--prefix=/opt`) and paths embedded in flags or assignments
  (`-Wl,-rpath,/usr/lib`, `DESTDIR=/tmp/x`), checked from every working
  directory the command could run in. A token is never exempt because it
  contains `@` or `://`: a remote or URL resolves inside the workspace as
  a relative name and yields no finding. Each path is resolved two ways and
  is outside if either escapes: with `..` collapsed first and symlinks
  resolved afterwards, and the way the kernel opens it, resolving a
  symlink before a following `..` (so `link/../secret` with `link`
  pointing outside the workspace is outside, even though the cleaned text
  names a file inside it). `passthrough` withholds the Nomos decision
  so Claude Code's own permission flow applies; it never turns into an
  `allow`, and a `deny` rule or an `ask` from another part of the same
  command still wins.

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

## Measure Before You Install

A hook that prompts on routine work gets disabled. Replay records the
decisions a profile would have made without running anything:

```bash
# your own Claude Code history, read-only (~/.claude/projects/**/*.jsonl)
nomos hook claude-code --replay-transcripts --profile safe-dev

# a file of recorded calls: corpus JSONL, hook input JSON, transcript lines, or plain commands
nomos hook claude-code --replay commands.jsonl --profile safe-dev --show-asks
```

The report counts allow, deny, and ask decisions, explains why calls ask
(refused syntax, a path outside the workspace, a rule that requires
approval, or no matching rule), lists the programs that ask most, and
prints every deny with its reason. `--format json` emits the same report
for scripts. Replay evaluates each call with the live pipeline, writes no
audit, and never executes a command.

[Validation against a real agent](validation-claude-code-hook.md) records
what happened when headless Claude Code sessions ran with the hook
installed, in default and bypass permission modes.

## Limits

- **Claude Code runs the hook, so its rules bound it.** Per the hooks
  reference, "A timed-out `command`, `http`, or `mcp_tool` hook doesn't
  block the tool call", and users can set `disableAllHooks`; organizations
  can restrict which hooks run with managed settings. The hook does no
  network I/O and evaluates in milliseconds; keep the timeout short and
  treat the hook as policy enforcement inside the harness, not as a
  sandbox around it.
- **Argv, not filesystem state.** Rules see normalized tokens. A file
  reached through an unusual spelling, a symlink created after the check,
  or a program that reads files by its own logic
  (`python script.py`) is decided by the rules that match that command,
  not by what it will touch. Option values are split on `,` and `=` only:
  a value glued to a multi-letter short option (`-XY/abs`) or a
  `:`-separated path list inside one value is checked as a single name,
  so a tool that interprets those reaches outside the workspace only if
  it is allowed with such arguments. Pair the hook with Claude Code's
  sandbox for OS-level containment.
- **Allowing an interpreter allows what it runs.** A rule that allows
  `python3 **`, `node **`, `make **`, or `npm run **` allows arbitrary
  code by construction (`python3 -c`, a Makefile recipe, an npm script);
  the argv the policy sees is exactly what runs, but what runs is a
  program. Allow interpreters only for workspaces you trust, and prefer
  patterns that name the script or subcommand. The default profiles ask
  (`safe-dev`) or deny (`ci-strict`, `prod-locked`) before the common
  inline forms (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`,
  `deno eval`) and before a bare interpreter or shell; flag clusters and
  glued forms (`-Bc`, `-c'code'`) are not recognized.
- **Opaque wrappers stay opaque.** `timeout 5 cmd`, `docker run ...`,
  `busybox sh -c ...`, and similar are evaluated as `timeout`, `docker`,
  or `busybox` commands; the hook does not look inside them. With the
  default profiles they have no allow rule and therefore ask.
- **Hooks run once per tool call.** Claude Code does not re-run the hook
  when a command it approved is retried, and the hook cannot see the
  effect of an approved command on later ones (for example a script it
  writes and then runs, which is decided as the interpreter call above).
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
| `--replay <file\|->` | | replay recorded tool calls and report the decisions |
| `--replay-transcripts`, `--transcripts-dir` | `~/.claude/projects` | replay every Claude Code transcript under a directory |
| `--format`, `--top`, `--show-asks` | `text`, `25` | replay report format, list length, and whether to list every ask |
