# Examples

## Start Here

[Local inbox](local-inbox/README.md) is the complete Python + LangGraph
example: an allowed draft, a denied recipient, a human-reviewed send, and
an audited local SQLite delivery. It runs without a model or service account.

Its `permissions.json` is also a standalone CI regression suite:

```bash
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

## Incident Regression Suites

[examples/incidents](incidents/README.md) turns documented coding-agent
incidents (home-directory wipes, secret reads through shell commands,
force pushes, `terraform destroy`) into `nomos test` suites for each default
profile. They run in `go test ./...` and in CI.

## Compatibility Examples

- [Quickstart configuration](quickstart/config.quickstart.json):
  existing direct HTTP/MCP smoke fixtures, with development-only credentials.
- [Go HTTP client](http-sdk/go/main.go), [Python HTTP client](http-sdk/python/quickstart.py),
  and [TypeScript HTTP client](http-sdk/typescript/quickstart.ts):
  direct built-in actions executed by the Go gateway.
- [OpenAI-compatible loop](openai-compatible/nomos_http_loop.py):
  an existing HTTP integration, not required for the account-free demo.
- [Policy samples](policies/): existing YAML/JSON policy formats.

Built-in callback-wrapper examples were removed because they could confuse
gateway execution with local execution. Use [CustomTool](../docs/http-sdk.md)
for a local callback, or the direct client for a built-in action.

Launcher and MCP configuration remain documented in the
[compatibility integration guide](../docs/integration-kit.md).

