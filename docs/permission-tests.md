# Permission Regression Tests

`nomos test` evaluates expected policy decisions offline. It does not run
tools, start a gateway, invoke an agent, or simulate approval storage.

```bash
nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

## Suite Format

Check the suite into your repository beside the policy:

```json
{
  "schema_version": "v1",
  "identity": {"principal": "developer", "agent": "inbox-demo", "environment": "dev"},
  "cases": [
    {
      "name": "sending requires review",
      "action": {
        "action_type": "email.send",
        "resource": "inbox://local/messages/message-1",
        "params": {"recipient": "reader@example.test", "body": "Hello"}
      },
      "expect": "REQUIRE_APPROVAL"
    }
  ]
}
```

Case names must be unique. Expected decisions are `ALLOW`, `DENY`, or
`REQUIRE_APPROVAL`. Optional `rules` lists assert the exact matching rule
IDs, ignoring order. Omit it when rule provenance is not part of the test.
Unknown fields and malformed actions are errors, not silently skipped tests.

The suite identity is explicit test input; real gateway identity still
comes from authentication. The runner uses the built-in bundle evaluator;
it does not test remote OPA behavior or runtime rate limits, approvals,
executor restrictions, authentication, or external tool execution.

## CI

Use the [complete GitHub Actions workflow](../README.md#catch-permission-regressions-in-ci)
to install a pinned release, verify its checksum, and test your checked-in
policy. It requires neither Go nor Python. Once Nomos is on the runner's
`PATH`, the test step is:

```yaml
- name: Test tool permissions
  run: nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml --format json
```

Change the suite and bundle paths to match your repository. To test changes
to Nomos itself, contributors can use `go run ./cmd/nomos test` instead.

Exit codes are 0 for all passing cases, 1 for a decision/rule mismatch,
and 2 for invalid input or a loading error. JSON reports include the policy
bundle hash, per-case expected/actual decisions, matching rules, and totals.

Before broadening a permission, add a negative case that should still be
denied. Use real-gateway integration tests for approval and execution
semantics; passing these fixtures alone is not a security assessment.
