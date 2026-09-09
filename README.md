# Nomos

Test tool permissions before you ship. Require human approval before a risky tool runs.

Nomos is an Apache-2.0 open-source permission layer for custom agent tools.
Start with a local Python + LangGraph workflow: drafts are allowed, blocked
recipients are denied, and sending requires review. No account, LLM API key,
Docker, or cloud deployment is needed to run it.

## Try It

Prerequisites: Go 1.25+ and Python 3.10+. Run from this checkout.
Go's automatic toolchain selection uses the patched version pinned in
`go.mod`; its first build may download that toolchain.

```bash
go build ./cmd/nomos
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e "./sdk/python[langgraph]"
python examples/local-inbox/demo.py
```

On Windows, use `py -3` instead of `python` to create the environment.
Activation is optional: use `.venv\Scripts\python.exe` directly in PowerShell.

The demo starts a temporary loopback gateway with fresh credentials, runs a
real checkpointed LangGraph workflow, and asks you to approve or reject a
message. Approved messages go to a **local SQLite inbox**, never real email.
It prints the directory containing the inbox, approvals, and audit records.
The Python package is installed from this checkout; it is not yet published
to PyPI.

[Step-by-step quickstart](docs/quickstart.md) ·
[Demo source](examples/local-inbox/demo.py) ·
[Permission tests](docs/permission-tests.md)

## Where It Fits

Use Nomos when your trusted application exposes tools such as `email.send`,
`ticket.close`, or `invoice.refund` and needs reviewable, testable permissions.
Your application owns the tool implementation and credentials. Nomos
evaluates its requested action and records the decision.

```python
from nomos_sdk import CustomTool

# client is an authenticated NomosClient; deliver is your trusted implementation.
send = CustomTool(
    client=client,
    action_type="email.send",
    resource=lambda p: "inbox://local/messages/" + p["message_id"],
    execute=deliver,
)
result = send.invoke(message)
# DENY / REQUIRE_APPROVAL never call deliver.
```

[Python integration and approval resume](docs/http-sdk.md) explains the
complete contract. The optional LangGraph adapter pauses for review and
rechecks authorization when resumed.

## Permissions As Tests

Check in action fixtures alongside your policy. Fail CI when an allow, deny,
or approval expectation changes:

```bash
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml --format json
```

These tests evaluate policy offline. They never execute a tool or start an
agent. The included suite covers allowed drafts, reviewed sends, blocked
recipients, export denial, unknown tools, and out-of-scope resources.

## Boundaries

- This is not a sandbox, prompt-injection detector, or replacement for an
  agent's native security controls. Direct tool access bypasses the wrapper.
- Custom tools execute in your trusted backend. Their outcome reports are
  caller-attested, not independently verified.
- Approval binds normalized inputs by default, not exactly-once execution.
  Use provider idempotency keys and durable checkpoints for real side effects.
- Keep reviewer credentials out of agent tools. The demo combines roles in
  one trusted script for learning, not process isolation.
- Local HTTP and temporary files are for development; protect credentials,
  storage, and transport in a real backend.

See [security scope](docs/assurance-levels.md) and
[approval authentication](docs/approvals.md).

## Contribute

Start with a small, runnable tool integration or a permission regression
fixture. We value a working example and a clear failure case over another
platform abstraction.

[Contributing](CONTRIBUTING.md) · [Tests](TESTING.md) · [Roadmap](docs/roadmap.md) ·
[Security reports](SECURITY.md)

The existing Go/TypeScript HTTP clients, MCP gateway, and coding-agent
launcher remain compatibility features; they are not prerequisites for the
new workflow. See [examples](examples/README.md) and the
[compatibility integration guide](docs/integration-kit.md).
