# Nomos

**Test AI tool permissions in CI. Require approval before execution.**

[![CI](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml/badge.svg)](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

[Install](#install) · [Quickstart](#quickstart) · [Claude Code Hook](docs/claude-code-hook.md) · [Python Guide](docs/http-sdk.md) · [Examples](examples/README.md) · [Roadmap](docs/roadmap.md) · [Contributing](CONTRIBUTING.md)

Nomos is an open-source permission layer for custom AI agent tools.
Your agent proposes an action; your application checks whether it is
allowed, denied, or needs human approval **before calling the tool**.

Write permission tests in Git. Wrap a Python tool. Pause a LangGraph
workflow for review. Start with a working local example—no account,
model API key, Docker, or cloud service required.

From the included [permission suite](examples/local-inbox/permissions.json)
(actual output, abbreviated):

```text
PASS draft is allowed: expected ALLOW, got ALLOW (rules: [inbox-allow-draft])
PASS delivery needs review: expected REQUIRE_APPROVAL, got REQUIRE_APPROVAL (rules: [inbox-review-send])
PASS deny wins over review: expected DENY, got DENY (rules: [inbox-deny-external-recipient])
...
6 passed, 0 failed | policy 170e4b90b50ea8a22b0d899292ba86c88e9f195a978d44cf5b106f37cfd46697
```

## Why Nomos?

Coding agents run with your shell and your credentials, and the failure
mode is documented rather than hypothetical. The Claude Code, Codex, Cline,
and Gemini CLI issue trackers hold seventeen primary reports, October 2025
to September 2026, of an agent recursively deleting files outside the
project, usually through a path or variable expansion inside a legitimate
cleanup task ([claude-code #10077](https://github.com/anthropics/claude-code/issues/10077),
[#83058](https://github.com/anthropics/claude-code/issues/83058),
[#95426](https://github.com/anthropics/claude-code/issues/95426),
[codex #46022](https://github.com/openai/codex/issues/46022)). Prompts alone
do not hold: Anthropic reports that "Claude Code users approve 93% of
permission prompts" and calls the result "approval fatigue"
([source](https://www.anthropic.com/engineering/claude-code-auto-mode)).
String-matched rules do not hold either: Claude Code's permissions
documentation says a Bash deny rule "isn't a security boundary around the
program", since `/bin/rm`, `bash -c`, and `git -C . push` step around it
([source](https://code.claude.com/docs/en/permissions)).

The asks in those reports converge: a gate on destructive actions keyed to
the target and enforced in every permission mode, rules whose semantics can
be trusted and tested, and a record of the command that ran and the rule
that decided it. Nomos is built for that:

- **Policy as code, tested in CI.** Allow, deny, and review expectations
  live in Git next to the code, and `nomos test` fails the build when a
  rule change turns a reviewed action into an automatic one.
- **Deny wins, in every mode.** Evaluation is deterministic and fails
  closed. Inside Claude Code, the hook's `deny` holds even under
  `--dangerously-skip-permissions`, and a command the parser cannot
  interpret safely is never auto-allowed.
- **Approval before execution.** Approvals bind to the exact arguments, and
  resuming a paused LangGraph workflow re-checks authorization instead of
  treating the resume as consent.
- **A record you can verify.** Decisions are logged with the argv that ran
  and the rule that fired, in a hash-linked chain you can re-verify
  (linked, not signed).
- **Your tools, your backend.** Implementation and provider credentials
  stay in trusted application code; Nomos supplies the decision and
  records reported outcomes.

Nomos is not an OS sandbox, a prompt-injection detector, or a substitute
for backups, and it decides only the calls that reach it: the Claude Code
hook routes that agent's native tools, and MCP, the HTTP gateway, and the
SDKs route the rest.

## Install

Install a prebuilt CLI—no Go toolchain or compilation needed.

### macOS — Homebrew

With [Homebrew](https://brew.sh/) installed:

```bash
brew install safe-agentic-world/nomos/nomos
nomos version
```

### Windows — Scoop

With [Scoop](https://scoop.sh/) installed, run in PowerShell:

```powershell
scoop bucket add nomos https://github.com/safe-agentic-world/scoop-nomos
scoop install nomos/nomos
nomos version
```

### Linux Or Direct Download

Download the archive for your OS and architecture from
[GitHub Releases](https://github.com/safe-agentic-world/nomos/releases/latest),
extract it, and place `nomos` (or `nomos.exe`) in a directory on your `PATH`.
Linux, macOS, and Windows binaries are available for x86-64 and ARM64.
See [release verification](docs/release-verification.md) for checksums and
signature verification. The Homebrew formula currently supports macOS only.

To upgrade, run `brew update` then `brew upgrade safe-agentic-world/nomos/nomos`,
or `scoop update` then `scoop update nomos`.

The quickstart requires **Nomos v0.13.3 or newer**. If `nomos test --help`
is unavailable, upgrade your installation before continuing.

Working on Nomos itself? See [building from source](docs/quickstart.md#build-from-source).

## Quickstart

Choose either path: **test a policy** with just the CLI, or **run a tool
with human review** using Python and LangGraph. You do not need LangGraph
for permission tests.

Install Nomos above, then use Git to download the example files and Python
SDK. Cloning the repository does not require building the CLI.

```bash
git clone https://github.com/safe-agentic-world/nomos.git
cd nomos
```

### Test A Policy

From the checkout:

```bash
nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

All six cases should pass: allowed drafts, reviewed sends, blocked
recipients, denied exports, unknown tools, and out-of-scope resources.
The suite evaluates policy locally—no server, Python, or tool execution.

### Enforce A Policy Inside Claude Code

Claude Code's own `Bash`, `Read`, `Write`, `Edit`, and `WebFetch` tools
never pass through an MCP server, so they need a hook. Register the Nomos
`PreToolUse` hook in the project's `.claude/settings.json`, then check what
it will do before Claude does (requires a release that includes
`nomos hook`; run `nomos hook claude-code --help` to check):

```bash
nomos hook claude-code --install --profile safe-dev
nomos hook claude-code --simulate --profile safe-dev --command "rm -rf tests/ patches/ plan/ ~/"
```

The second command prints the decision Claude Code would receive:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Nomos: profile safe-dev denies process.exec [\"rm\" \"-rf\" \"tests/\" \"patches/\" \"plan/\" \"~/\"] (rules: safe-dev-deny-catastrophic-delete)"}}
```

Allowed commands such as `git status && go test ./...` skip the prompt,
`git push` asks for confirmation, `cat config/.env` is denied, and a
command with variable or command substitution asks, because Nomos will not
guess what the shell would run. Commit `.claude/settings.json` to share the
rule set, keep the profile or bundle in Git, and gate changes with
`nomos test`. Each decision is appended to `.nomos/claude-code-hook.jsonl`,
which `nomos hook claude-code --verify-audit` re-checks.

[Hook guide, decision table, and limits](docs/claude-code-hook.md) ·
[Codex hook](docs/codex-hook.md) (`nomos hook codex --install --profile safe-dev`)

### Run A Tool With Human Review

The demo uses Python 3.10+, real LangGraph, and a local SQLite inbox.
It can use the installed `nomos` binary on your `PATH`; no Go build is needed.
Run these commands from the checkout above.

**macOS / Linux**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e "./sdk/python[langgraph]"
.venv/bin/python examples/local-inbox/demo.py
```

<details>
<summary><strong>Windows PowerShell</strong></summary>

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -e "./sdk/python[langgraph]"
.venv\Scripts\python.exe examples/local-inbox/demo.py
```

No environment activation or PowerShell execution-policy change is needed.

</details>

The script starts its own loopback gateway and asks you to review a message.
Enter `y` to approve, or anything else to reject. An approved run looks
like this (output abbreviated):

```text
ALLOW: draft prepared
DENY: blocked recipient, delivery did not run
REQUIRE_APPROVAL: delivery paused
...
Deliver this message to the local inbox? [y/N] y
DELIVERED: {"message_id": "welcome-1", "status": "delivered_to_local_inbox"}
```

No email leaves your machine. Requests are scripted; policy evaluation,
review, and local delivery are real. The printed temporary directory
contains the inbox, approvals, and audit records **plus development
credentials**. Keep it private and remove that directory when finished.

The Python SDK is installed from this checkout; these instructions do not
depend on a PyPI release. Internet access is needed for installation, not
for the local demo.

[Detailed walkthrough and prerequisites](docs/quickstart.md) ·
[Demo source](examples/local-inbox/demo.py)

## Connect Your Own Tool

Give your tool a domain action such as `email.send` and a resource URI
that your policy can match. The callback runs only after an explicit
external authorization from Nomos.

```python
from nomos_sdk import CustomTool

# Integration sketch: client is an authenticated NomosClient,
# and deliver_message is your trusted backend function.
send = CustomTool(
    client=client,
    action_type="email.send",
    resource=lambda p: "inbox://local/messages/" + p["message_id"],
    execute=deliver_message,
)

request = send.prepare({
    "message_id": "welcome-1",
    "recipient": "reader@example.test",
    "body": "Hello!",
})
result = send.run(request)
# DENY or REQUIRE_APPROVAL: deliver_message has not run.
```

For approval-gated actions, a separately authorized reviewer records the
decision. Retry the saved request with its approval ID; the default
fingerprint binding rejects changed arguments, rejected approvals, and
expired approvals.

See the [complete Python and LangGraph guide](docs/http-sdk.md) for client
setup, review/resume, and failure handling. The inbox is the runnable
reference; other domain action names are not prebuilt provider connectors.

## Catch Permission Regressions In CI

Copy the [permission suite](examples/local-inbox/permissions.json) and
[policy](examples/local-inbox/policy.yaml) into your repository, preserving
those paths or changing the final command below. Save this complete workflow
as `.github/workflows/permissions.yml`. It installs a pinned release and
checks the archive's pinned SHA-256 before running tests—no Go or Python needed.

```yaml
name: Tool permissions
on: [push, pull_request]
permissions:
  contents: read
jobs:
  permissions:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          persist-credentials: false
      - name: Install Nomos
        env:
          NOMOS_VERSION: v0.13.3
          NOMOS_SHA256: d0de367cfc407595530cf7bb8862b4b6bf52698a929ff7ec79ed2ac2d26596f2
        shell: bash
        run: |
          set -euo pipefail
          install_dir="$(mktemp -d "${RUNNER_TEMP}/nomos.XXXXXX")"
          cd "${install_dir}"
          curl --fail --silent --show-error --location --retry 3 \
            "https://github.com/safe-agentic-world/nomos/releases/download/${NOMOS_VERSION}/nomos-linux-amd64.tar.gz" \
            --output nomos.tar.gz
          echo "${NOMOS_SHA256}  nomos.tar.gz" | sha256sum --check --strict
          tar -xzf nomos.tar.gz nomos
          echo "${install_dir}" >> "${GITHUB_PATH}"
      - name: Test tool permissions
        run: nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml --format json
```

This example targets Linux x86-64 runners. When upgrading, update both the
version and checksum from the [verified release](docs/release-verification.md).

Exit codes: `0` for a passing suite, `1` for a decision or rule mismatch,
and `2` for invalid input or a loading error. JSON output includes
per-case results and the policy bundle hash.

These are policy tests, not runtime security tests. Authentication,
approval storage, and actual tool execution need integration coverage.
Read the [suite format and CI guide](docs/permission-tests.md).

## What Ships Today

| Interface | What You Can Use |
| --- | --- |
| CLI | Offline permission regression tests with text/JSON reports |
| Claude Code hook | Policy decisions for native shell, file, and fetch tools; `deny` holds in every permission mode; hash-linked local audit |
| Codex hook | The same decisions for Codex's `Bash` and `apply_patch` calls through its `PreToolUse` and `PermissionRequest` hooks; fails closed where Codex cannot ask; contract verified and reviewed from source, live run pending |
| Python SDK | Custom-tool authorization and automatic outcome reporting |
| LangGraph adapter | Checkpointed review pauses and authorization checks on resume |
| Local inbox example | Account-free allow, deny, approval, and SQLite delivery |
| Go / TypeScript clients | HTTP clients and generic custom-action guards; application-owned review/reporting |
| MCP / coding-agent launcher | Retained compatibility integrations, not required for the workflow above |

The Python base client has no third-party runtime dependencies; LangGraph
is an optional extra. The Go gateway runs separately.

For existing users, see the [compatibility guide](docs/integration-kit.md)
and [migration notes](CHANGELOG.md). Built-in actions execute inside
Nomos; use direct client calls for those, not local callback guards.

## Security Boundaries

- **Route every relevant tool call through the guard.** Direct provider
  access bypasses it. The application, policy, and credentials must remain
  outside agent control.
- **Separate reviewer authority.** Keep reviewer credentials out of agent
  tools. The demo combines both roles in one trusted script, not isolated
  processes.
- **Plan for retries.** Approval is not an exactly-once execution token.
  Real providers need idempotency keys; restartable workflows need durable
  checkpoints. The demo's graph checkpoints are in memory.
- **Treat reports as claims, not delivery proof.** Custom tools execute in
  your backend; Nomos does not independently verify their reported outcomes.
- **Protect real deployments.** Local HTTP and temporary credentials are
  development conveniences, not a production configuration.
- **A hook is bounded by the harness that runs it.** Claude Code does not
  block a call when a hook times out, and users can disable hooks in their
  settings. Keep the timeout short, prefer managed settings on shared
  machines, and treat the hook as policy enforcement inside the harness,
  not as a sandbox around it.

[Security scope](docs/assurance-levels.md) ·
[Approval authentication](docs/approvals.md) ·
[Report a vulnerability privately](SECURITY.md)

## Contribute

You do not need to understand the entire codebase to help.

- **Try the quickstart:** [report the exact step that failed or confused you](https://github.com/safe-agentic-world/nomos/issues/new?template=bug_report.yml).
- **Add a regression case:** contribute a small policy and an action that
  should stay denied or require review.
- **Connect one tool:** [propose a concrete integration](https://github.com/safe-agentic-world/nomos/issues/new?template=integration_request.yml)
  with an account-free test path and clear retry behavior.
- **Improve the docs:** a verified command or clearer example is a useful PR.

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[roadmap](docs/roadmap.md). Focused integrations and reproducible failure
cases are the priority; hosted accounts and cluster orchestration are not.

To check a Go change:

```bash
go test ./...
go vet ./...
```

[TESTING.md](TESTING.md) covers SDK, LangGraph, MCP, packaging, and race
checks. See the [local validation record](docs/validation.md) for tested
behavior and known verification limits.

## License

[Apache-2.0](LICENSE). Build with it, inspect it, and contribute back.
