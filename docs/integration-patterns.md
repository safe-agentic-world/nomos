# Integration Patterns

## Custom Application Tools

Start with the [Python SDK and LangGraph integration](http-sdk.md) when your
application owns the tool implementation. Use a domain action such as
`email.send`, map its arguments to a stable resource, and check permissions
before invoking the trusted callback.

The [local inbox example](../examples/local-inbox/README.md) is the complete
reference. No provider account or model is required.

## Built-In Actions

Built-in filesystem, process, HTTP, patch, and secret actions execute in
Nomos itself. Call the direct HTTP client and consume its result; do not
execute a second local side effect after an ALLOW response. Specialized
built-in callback guards now reject invocation to prevent this ambiguity.

## MCP Compatibility

Existing MCP users can keep the [MCP integration](integration-kit.md).
MCP is not required for the custom-tool workflow. Tools connected directly
to an agent instead of through Nomos remain outside its boundary.

## Raw HTTP

Use the [HTTP contract](http-integration-kit.md) when your language or
runtime has no adapter. Custom actions require `external_authorized`
execution mode before local execution. Go and TypeScript generic guards
handle the decision gate; application code owns review orchestration and
outcome reporting.

Always keep reviewer credentials separate, recheck approval on resume,
and use provider idempotency for real side effects.
