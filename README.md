# Nomos

**Test permissions. Review risky actions. Keep your agent tools.**

[![CI](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml/badge.svg)](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

[Quickstart](#quickstart) · [Python Guide](docs/http-sdk.md) · [Examples](examples/README.md) · [Roadmap](docs/roadmap.md) · [Contributing](CONTRIBUTING.md)

Nomos is an open-source permission layer for custom AI agent tools.
Your agent proposes an action; your application checks whether it is
allowed, denied, or needs human approval **before calling the tool**.

Write permission tests in Git. Wrap a Python tool. Pause a LangGraph
workflow for review. Start with a working local example—no account,
model API key, Docker, or cloud service required.

## Why Nomos?

A working tool call is not necessarily an authorized one. An assistant
might be allowed to draft a message but need approval to send it.
A policy change should not silently turn that reviewed send into an
automatic one.

Nomos makes those expectations explicit:

- **Permissions as tests:** check allow, deny, and review expectations
  alongside your code, then catch regressions in CI.
- **Approval before execution:** pause a real LangGraph workflow and
  recheck authorization when it resumes. Resuming is not itself approval.
- **Your tools, your backend:** keep your implementation and provider
  credentials in trusted application code. Nomos supplies the decision
  and records reported outcomes.

Use it when you own the application exposing the tools and want testable
permissions outside the prompt. It complements your framework and runtime
controls; it is not a sandbox or a prompt-injection detector.

## Quickstart

### 1. Test Permissions Without Running An Agent

You need Git and Go 1.25+. Go automatically selects the patched toolchain
pinned in [go.mod](go.mod); the first run may download it and dependencies.

```bash
git clone https://github.com/safe-agentic-world/nomos.git
cd nomos
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

All six cases should pass: allowed drafts, reviewed sends, blocked
recipients, denied exports, unknown tools, and out-of-scope resources.
The suite evaluates policy locally—no server, Python, or tool execution.

### 2. Run A Tool With Human Review

The demo uses Python 3.10+, real LangGraph, and a local SQLite inbox.
Build the Go gateway from the same checkout:

```bash
go build ./cmd/nomos
```

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

`CustomTool` reports execution outcomes automatically. If delivery
succeeds but reporting fails, it raises `OutcomeReportError` with the
result retained—retry the report, not the side effect.

See the [complete Python and LangGraph guide](docs/http-sdk.md) for client
setup, review/resume, and failure handling. The inbox is the runnable
reference; other domain action names are not prebuilt provider connectors.

## Catch Permission Regressions In CI

Keep a [permission suite](examples/local-inbox/permissions.json) beside
your [policy](examples/local-inbox/policy.yaml). After checkout and Go
setup, add this step to your workflow:

```yaml
- name: Test tool permissions
  run: go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml --format json
```

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
