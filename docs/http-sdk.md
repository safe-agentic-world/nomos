# Custom Tools With Python

Install from the repository root:

```bash
python -m pip install -e "./sdk/python"
# Optional, for the real LangGraph adapter:
python -m pip install -e "./sdk/python[langgraph]"
```

Python 3.10+ is required. The base client uses only the standard library.
The Go gateway is a separate process; the package does not bundle it.

## Authorize, Execute, Report

Create a `NomosClient` with your gateway URL, principal bearer token,
agent ID, and agent HMAC secret. Load credentials from trusted configuration,
never model-generated arguments. See the [complete local demo](../examples/local-inbox/demo.py)
for a working setup with generated credentials.

```python
from nomos_sdk import CustomTool

send = CustomTool(
    client=client,
    action_type="email.send",
    resource=lambda p: "inbox://local/messages/" + p["message_id"],
    execute=deliver,
)
request = send.prepare({
    "message_id": "message-123",
    "recipient": "reader@example.test",
    "body": "Hello",
})
result = send.run(request)
```

`prepare` snapshots JSON input and assigns stable correlation IDs.
`run` calls Nomos before invoking your callback. Only `ALLOW` with
`execution_mode: external_authorized` permits local execution.
Denials, approval requests, invalid responses, and transport failures do
not invoke the callback.

Nomos does not implement `deliver`: use your trusted provider integration.
Keep its credentials and direct execution entrypoint inaccessible to the
agent. A wrapper around an agent-accessible function is not isolation.

## Approve And Resume

When `result.requires_approval()` is true, show the reviewer the saved
request and `result.decision_response["approval_id"]`.

A **separately authorized reviewer** records `APPROVE` or `DENY` using
`reviewer.decide_approval(approval_id, "APPROVE")`. The reviewer principal
must be configured in `approvals.approver_principals`. Never expose that
client as an agent tool.

Retry `send.run(request, approval_id=approval_id)` with the original
snapshot. Fingerprint-bound approval rejects changed arguments and expired
or denied approval records. Approval is not consumed exactly once.

## LangGraph

```python
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from nomos_langgraph import tool_graph

graph = tool_graph(send, checkpointer=InMemorySaver())
config = {"configurable": {"thread_id": "review-123"}}
state = graph.invoke({"params": request.params}, config)
# If state contains __interrupt__, the separate reviewer decides in Nomos.
# Only after that decision:
state = graph.invoke(Command(resume=True), config)
```

The graph checkpoints the prepared request before review. Resuming a graph
does not grant approval; execution always rechecks Nomos. Use a durable
checkpointer outside this demo. LangGraph can re-run interrupted nodes;
place side effects only in the guarded execution callback and use stable
provider idempotency keys. See
[LangGraph interrupt semantics](https://docs.langchain.com/oss/python/langgraph/interrupts).

## Failure And Retry Rules

`CustomTool` automatically reports SUCCEEDED or FAILED without sending
the callback's output or exception text. A failed callback is re-raised;
it may already have caused a side effect. No automatic retry occurs.

If execution succeeds but recording fails, `OutcomeReportError` retains
`result` and `report`. Reconcile the provider result and retry
`client.report_external_outcome(error.report)`, not the tool.
Repeated reports can produce repeated audit entries. Reports are
caller-attested and do not prove provider delivery.

## Compatibility And Migration

Go (`pkg/sdk`) and TypeScript (`sdk/typescript`) retain their HTTP
clients and generic custom-action guards. They do not yet provide this
Python adapter's automatic outcome reporting or LangGraph workflow.

Built-in actions such as `net.http_request` and `process.exec` already
execute inside Nomos. Use the client's direct action method for those.
Old specialized HTTP/process/file callback guards now reject invocation:
running a built-in and a local callback could perform the side effect twice.
Migrate local callbacks to explicit custom action names and matching policy;
do not silently reuse built-in policy permissions.

See [the HTTP contract](http-integration-kit.md) and
[custom action semantics](custom-actions.md).
