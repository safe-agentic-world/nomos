# Local Validation Plan

Follow [TESTING.md](../TESTING.md) for exact commands.

## Required Acceptance Checks

1. Build the CLI and run the offline inbox permission suite: all six
   allow/deny/review expectations must pass.
2. Install the Python SDK with its LangGraph extra into a fresh virtual
   environment. No repository-relative import hacks should be needed.
3. Run Python unit and real-gateway integration tests.
4. Run the inbox demo once with approval and once with rejection. Only the
   approved case may create a delivered message.
5. Check denied, expired, rejected, changed-argument, unauthorized-reviewer,
   and forged graph-resume paths. No callback may run in these cases.
6. Verify execution/report failure handling and local provider idempotency.
7. Run the full Go suite, vet, available race tests, TypeScript tests, doc
   link checks, and workflow lint.
8. Build a Python wheel and import it from a fresh environment outside the
   checkout. Do not publish as part of local validation.

## Compatibility Checks

Keep the original quickstart policy, doctor, CLI, normalization, bypass,
and MCP tests green. The coding-agent job runner and broad deployment
guides are intentionally removed; do not recreate them as prerequisites.

## Evidence And Limits

Record actual commands, failures, and toolchain limits in the handoff.
A passing offline suite tests policy, not runtime isolation.
A successful local inbox delivery does not validate an external email
provider or exactly-once delivery. Demo state and credentials stay in the
printed temporary directory until the developer removes that directory.
