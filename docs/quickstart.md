# Quickstart

Run a permission-controlled tool workflow locally. Nothing is sent to an
email provider; requests are scripted, but Nomos and LangGraph are real.

## Build And Test Permissions

From the repository root, with Go 1.25+:

```bash
go build ./cmd/nomos
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

All six cases should pass. An unexpected decision exits 1; malformed input
exits 2. No gateway, model, or Python dependency is needed for these tests.

## Install The Python Integration

Use Python 3.10+ in a virtual environment.

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e "./sdk/python[langgraph]"
.venv/bin/python examples/local-inbox/demo.py
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -e "./sdk/python[langgraph]"
.venv\Scripts\python.exe examples/local-inbox/demo.py
```

Internet access is needed to install dependencies, not to run the demo.
The SDK is installed from this checkout, not a published PyPI release.

## Review The Result

The script starts its own loopback gateway with a fresh policy copy,
separate agent/reviewer keys, and temporary SQLite stores. It demonstrates:

1. An allowed draft and a blocked recipient.
2. A send paused at a LangGraph interrupt, before delivery.
3. Your terminal approval or rejection, followed by a fresh authorization check.
4. A delivered local inbox entry only after approval.

Answer `y` to approve; any other answer rejects. `--auto-approve` and
`--reject` are explicit scripted test modes, not production review flows.
Use `--nomos /path/to/nomos` if your binary is elsewhere.

The printed temporary directory retains `inbox.db`, `approvals.db`,
`audit.db`, and logs for inspection. It also contains development
credentials in `config.json`; do not publish it. Delete that specific
directory when finished. Windows file mode bits do not establish a separate
security boundary.

## Connect Your Tool

Read [the Python guide](http-sdk.md), then replace the local delivery
function with one trusted backend tool. Add allow/deny/review cases to a
[permission suite](permission-tests.md) before using real credentials.
Keep approval credentials outside the agent's accessible tools.

This sample uses an in-memory LangGraph checkpointer and SQLite
idempotency for local messages. Production restart/resume needs a durable
checkpointer and the real provider's idempotency mechanism.

## Compatibility Smoke

Existing HTTP/MCP users can still run these commands with `nomos` on PATH:

```powershell
nomos doctor -c .\examples\quickstart\config.quickstart.json --format json
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml
nomos serve -c .\examples\quickstart\config.quickstart.json
```

These are separate compatibility fixtures, not the isolated inbox demo.
See [the compatibility guide](integration-kit.md).

