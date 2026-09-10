# Nomos

**Test AI tool permissions in CI. Require approval before execution.**

[![CI](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml/badge.svg)](https://github.com/safe-agentic-world/nomos/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

[Install](#install) · [Quickstart](#quickstart) · [Agent Example](#standalone-agent-example) · [Python Guide](docs/http-sdk.md) · [Examples](examples/README.md) · [Roadmap](docs/roadmap.md) · [Contributing](CONTRIBUTING.md)

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

Want a model-driven application instead of scripted requests? Try
[DispatchDesk](#standalone-agent-example), a separate support agent that uses
Nomos through its public SDK.

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

## Standalone Agent Example

[DispatchDesk](https://github.com/safe-agentic-world/nomos-customer-support-agent)
is a separately packaged support agent with a real local Ollama model. It reads
tickets, drafts replies, and—with Nomos enabled—pauses sends and refunds for
review. Its application owns the tools and SQLite data; Nomos supplies
authorization through the public Python SDK.

- **Without Nomos:** run the agent in read/draft-only mode.
- **With Nomos:** review through a separate reviewer CLI, then restart and
  resume the agent with a fresh authorization check before execution.
- **As a compatibility test:** check tenant isolation, approval expiry,
  changed payloads/recipients, gateway outages, and duplicate execution.

To try its policy suite, install Nomos above and clone the example into a
separate directory:

```bash
git clone https://github.com/safe-agentic-world/nomos-customer-support-agent.git
cd nomos-customer-support-agent
nomos test --suite policies/permissions.json --bundle policies/support.yaml
```

All eight cases should pass, without Python or a running model. For the live
agent, follow the [setup and review walkthrough](https://github.com/safe-agentic-world/nomos-customer-support-agent#add-nomos)
(Python 3.10+, Ollama, and an installed local model).

Sends and refunds create **local records only**—no email is delivered and no
money moves. DispatchDesk is maintained by the Nomos author as a reference
application, not an independent customer endorsement. Its
[validation record](https://github.com/safe-agentic-world/nomos-customer-support-agent/blob/main/VALIDATION.md)
covers live-model runs, CI results, and known limitations.

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
| Python SDK | Custom-tool authorization and automatic outcome reporting |
| LangGraph adapter | Checkpointed review pauses and authorization checks on resume |
| Local inbox example | Account-free allow, deny, approval, and SQLite delivery |
| [DispatchDesk](https://github.com/safe-agentic-world/nomos-customer-support-agent) | Standalone Ollama support agent, durable tools, and public-SDK compatibility tests |
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
