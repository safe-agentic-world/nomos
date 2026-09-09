# Nomos Python SDK

Install from the repository: `python -m pip install ./sdk/python`.
For the LangGraph adapter: `python -m pip install './sdk/python[langgraph]'`.
These commands build locally; no public package release is assumed.

Import `NomosClient`, `ActionRequest`, and `CustomTool` from `nomos_sdk`.
The standard-library SDK needs a running Nomos gateway. The Go gateway is
installed separately; installing this package does not install the server.

Start with the repository's `examples/local-inbox` demo and `docs/http-sdk.md`.
The optional `nomos_langgraph` adapter uses LangGraph checkpoints and interrupts;
it does not implement an agent framework or require an LLM account.

Custom tools run in your trusted application, not inside Nomos. Keep credentials
and approval controls out of model-accessible tools. Use provider idempotency for
real side effects: authorization is not an exactly-once execution guarantee.
