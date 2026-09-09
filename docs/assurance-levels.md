# Security Scope And Assurance Labels

Nomos evaluates actions routed through it. It does not control actions
that bypass it, inspect model reasoning, or replace runtime isolation.

## Custom Tools

The Python integration asks the Go gateway for permission before invoking
a trusted local callback. DENY and REQUIRE_APPROVAL do not execute that
callback. An approval resume is authorized again against the current
policy and the saved action.

These properties depend on your application routing every relevant tool
through the wrapper and keeping policy, identity, and reviewer credentials
outside agent control. An agent with direct provider credentials can bypass
this boundary.

External outcome reports are caller-attested. Nomos cannot independently
verify that the provider performed the reported operation. Approval IDs
and action IDs are not exactly-once execution tokens. Real integrations
need provider idempotency and reconciliation.

## Compatibility Labels

Older HTTP, MCP, launcher, and doctor surfaces retain the labels
`STRONG`, `GUARDED`, and `BEST_EFFORT` for compatibility. These are
runtime/configuration assessments, not certifications or proofs that all
agent side effects are intercepted.

`BEST_EFFORT` describes unmanaged environments. Stronger labels depend
on configured identity, egress, and sandbox assumptions. A deployment-mode
string alone does not establish isolation. The local inbox demo runs in
unmanaged mode and makes no host-containment claim.

## Approval And Storage Boundaries

Remote approval decisions require an authenticated principal explicitly
listed in `approvals.approver_principals`. Empty lists authorize nobody.
Webhook approval routes are disabled unless their specific tokens are set.
A user with direct approval-store access remains a trusted operator.

The demo stores development credentials and SQLite databases in a temporary
directory. Its in-memory LangGraph checkpoint does not survive restart.
Operating-system access controls, secure transport, backups, and durable
application orchestration remain your responsibility.

See [deployment guidance](deployment.md), [approval binding](approvals.md),
and [the threat model](threat-model.md).
