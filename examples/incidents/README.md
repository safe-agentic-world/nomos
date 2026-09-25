# Incident Regression Suites

These permission suites turn documented coding-agent incidents into
checked-in regression tests for the three default profiles. Each case is
an action shape taken from a public report, evaluated offline with
`nomos test`, and expected to be denied, sent for review, or allowed.

```bash
nomos test --suite examples/incidents/safe-dev.permissions.json --bundle profiles/safe-dev.yaml
nomos test --suite examples/incidents/ci-strict.permissions.json --bundle profiles/ci-strict.yaml
nomos test --suite examples/incidents/prod-locked.permissions.json --bundle profiles/prod-locked.yaml
```

The Go test suite runs all three, and CI runs them with the built binary.
They evaluate policy only: no shell runs, no file is touched, and the
outcome says nothing about a sandbox or the agent's own permission system.

## Incident Classes And What Each Suite Asserts

| Class | Documented examples | Suite expectation |
| --- | --- | --- |
| Recursive delete escaping the project (home directory, drive or filesystem root, parent directory) | [claude-code #10077](https://github.com/anthropics/claude-code/issues/10077), [#12637](https://github.com/anthropics/claude-code/issues/12637), [#83058](https://github.com/anthropics/claude-code/issues/83058), [#93099](https://github.com/anthropics/claude-code/issues/93099), [#95426](https://github.com/anthropics/claude-code/issues/95426), [codex #46022](https://github.com/openai/codex/issues/46022), [codex #40329](https://github.com/openai/codex/issues/40329), [gemini-cli #4586](https://github.com/google-gemini/gemini-cli/issues/4586) | `rm`/`rmdir` targeting `~`, `/`, any absolute path, or a parent directory: `DENY` by the profile's `deny-catastrophic-delete` rule. A workspace-relative delete has no allow rule and is denied by default. |
| Secret material read or staged through a shell command instead of a file tool | [claude-code #84863](https://github.com/anthropics/claude-code/issues/84863), [#93002](https://github.com/anthropics/claude-code/issues/93002), [#401](https://github.com/anthropics/claude-code/issues/401), [codex #2847](https://github.com/openai/codex/issues/2847) | `cat .env`, `head .env.production`, `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `git add .env`, `cp server.pem /tmp/`: `DENY` by `deny-exec-secret-file-args`, whatever the command and wherever the argument sits. Direct `fs.read` of the same paths stays denied. |
| Destructive git | [claude-code #33402](https://github.com/anthropics/claude-code/issues/33402), [#11237](https://github.com/anthropics/claude-code/issues/11237) | `git push --force`, `git reset --hard HEAD~5`, `git clean -fdx`: `REQUIRE_APPROVAL` in `safe-dev`, `DENY` in `ci-strict` and `prod-locked`. |
| Infrastructure and database mutation | [Docker's Kiro account](https://www.docker.com/blog/coding-agent-horror-stories-the-agent-that-deleted-production/), [claude-code #93002](https://github.com/anthropics/claude-code/issues/93002), [#95201](https://github.com/anthropics/claude-code/issues/95201) | `terraform destroy`, `kubectl delete`, `psql`: `REQUIRE_APPROVAL` in `safe-dev`, `DENY` in `ci-strict` and `prod-locked`. |
| Credential-bearing or unexpected egress | [Docker on GitHub MCP exfiltration](https://www.docker.com/blog/coding-agent-horror-stories-the-command-you-already-approved/), [Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing) | An `Authorization` header on any request: `DENY`. A host that no rule lists: `DENY` by default. |
| Privilege escalation and secret checkout | [claude-code #84863](https://github.com/anthropics/claude-code/issues/84863) | `sudo ...` has no allow rule; `secrets.checkout` is denied. |

Allowed cases (`git status`, `go test`, reading source files, GitHub
`GET` requests) are included so a profile change that over-blocks fails
the suite too.

## What These Suites Do Not Prove

- They exercise the policy engine, not the agent. Claude Code's native
  tools reach this policy only through the
  [PreToolUse hook](../../docs/claude-code-hook.md); other agents reach it
  through MCP, the HTTP gateway, or the SDKs.
- Variable and command substitution (`rm -rf $HOME`, `rm -rf "$(pwd)"`)
  cannot be expressed as argv here. The hook refuses to interpret such
  commands and asks for confirmation (or denies under `--on-unsupported deny`);
  see the hook tests in `internal/agenthook`.
- Argument patterns match tokens, not filesystem state. A symlink or an
  unusual spelling of a path is a matter for the hook's workspace check
  and for an OS sandbox, which Nomos is not.

The issue links above were re-fetched and verified on 2026-09-25; each
suite case is a simplified action shape, not a transcript of the report.
