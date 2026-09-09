# Developer-Adoption Roadmap

## This Iteration's End Goal

A contributor can install from a checkout, run a real permission-and-review
workflow without an account, inspect the outcome, and add a regression test
before connecting one custom tool. The project should explain where it
fits without requiring knowledge of an enterprise control plane.

Delivered interfaces:

- `nomos test`: deterministic offline allow/deny/review fixtures with CI exits.
- Installable Python SDK with optional LangGraph adapter.
- Real local inbox delivery, reviewer authentication, and outcome reporting.
- Negative tests for approval and execution boundaries.
- Focused onboarding; broad deployment/job-runner material removed.

See [the validation checklist](local-validation-plan.md) for acceptance
checks and [local verification results](validation.md). Packaging locally
does not imply publication to PyPI.

## Small Contributions To Validate Next

1. **First-run feedback:** reproduce the quickstart on a fresh machine and
   report the exact step that caused confusion.
2. **Permission cases:** contribute a minimal policy and denied edge case,
   especially for unexpected tool arguments and out-of-scope resources.
3. **Durable LangGraph example:** demonstrate stop/restart during review with
   a supported persistent checkpointer and a crash/replay regression test.
4. **One real connector:** propose a specific ticket or notification tool,
   including account-free tests and provider idempotency behavior.
5. **SDK parity:** bring the proven custom-tool outcome/reporting contract
   to TypeScript or Go with equivalent failure tests.

Open an integration request before building a new abstraction. Shipping a
small working example is more useful than listing unsupported frameworks.

## Not Planned In This Direction

Hosted accounts, billing, cluster manifests, Helm packaging, infrastructure
orchestration, and a standalone coding-agent job platform. Existing MCP and
launcher interfaces remain compatibility features, not the primary roadmap.

Adoption and popularity are outcomes to validate with users, not guarantees.
Prioritize successful first runs, contributors connecting a real tool, and
actionable issue reports over adding more surface area.
