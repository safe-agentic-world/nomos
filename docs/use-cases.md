# Use Cases

## Runnable Today: Reviewed Tool Calls

The [local inbox example](../examples/local-inbox/README.md) demonstrates a
custom agent tool with allowed drafts, denied recipients, reviewed sends,
and real local SQLite delivery. It is a reference integration, not a claim
of customer adoption or a production email connector.

## Runnable Today: Permission Regression Tests

Use [offline permission suites](permission-tests.md) in a pull request to
detect when policy edits accidentally allow a previously denied action or
remove a required review. These tests need no running server or agent.

## Next Integration Candidates

Ticket updates, outbound notifications, and repository issue creation are
possible applications of the same custom-tool contract. They are proposals,
not shipped connectors. Each needs a concrete backend implementation,
minimal permissions, provider idempotency, and account-free failure tests.

Nomos is not targeting cluster operations, general infrastructure
orchestration, or a replacement security layer for coding-agent products.
See [the roadmap](roadmap.md) to propose one bounded workflow.
