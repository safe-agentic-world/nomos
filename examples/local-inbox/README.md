# Local Inbox: Python + LangGraph

A complete, account-free custom-tool integration. Tool requests are
scripted; LangGraph, the Go gateway, policy evaluation, approval storage,
audit storage, and SQLite delivery are real. No email leaves your machine.

## Run

From the repository root, build `go build ./cmd/nomos`, create a Python
3.10+ virtual environment, and use its Python executable:

```bash
python -m pip install -e "./sdk/python[langgraph]"
python examples/local-inbox/demo.py
```

See the [quickstart](../../docs/quickstart.md) for Windows and Unix setup.
Answer `y` at the prompt to approve, or any other answer to reject.
`--auto-approve` and `--reject` exercise scripted test paths.

## Files And Behavior

- `policy.yaml`: allow drafts, require review for sends, deny blocked
  recipients and exports, deny everything else by default.
- `permissions.json`: six offline policy regression cases.
- `demo.py`: isolated loopback gateway, reviewer client, graph, and a
  real local delivery function with stable-message-ID deduplication.
- `test_integration.py`: real-gateway approval and execution regressions.

The script prints a temporary artifact directory and stops the gateway
when finished. Inspect its SQLite inbox, approvals, and audit database.
The directory also holds development credentials; keep it private and
delete that specific directory after inspection.

## Adapt One Tool

Replace `deliver` with your trusted provider callback, choose a custom
action name and resource URI, and add policy cases before connecting real
credentials. Keep reviewer access separate from agent tools. The example
combines roles in one trusted script for demonstration only.

LangGraph's in-memory checkpoint does not survive restart. A real provider
needs a durable checkpoint and its own idempotency mechanism. Nomos
approval is not an exactly-once token, and external reports are
caller-attested. See [the SDK guide](../../docs/http-sdk.md).
