# Running Nomos

The supported first-use workflow is the [local inbox demo](quickstart.md).
It needs a Go binary, Python, and optional LangGraph dependencies, not a
cluster or control-plane installation.

## Local Development

`python examples/local-inbox/demo.py` starts and stops its own loopback
gateway. Its random credentials and stores live in the printed temporary
directory. Do not reuse this generated configuration for a shared service.

For an existing configuration, run:

```bash
nomos doctor -c path/to/config.json --format json
nomos serve -c path/to/config.json
```

The checked-in compatibility configuration at
`examples/quickstart/config.quickstart.json` contains development fixtures,
not production credentials.

## Trusted Application Backend

Place Nomos next to the application that owns custom tool execution.
The model may propose arguments; it must not control identity, policy,
reviewer credentials, or an alternate direct provider client.

- Bind development HTTP to loopback. Use authenticated TLS for remote access.
- Keep policy, approval stores, audit stores, and configuration writable only
  by trusted operators.
- Give agents only their application credentials. Configure separate
  reviewer principals in `approvals.approver_principals`.
- Use fingerprint approval scope for argument-specific review.
- Use durable application checkpoints and provider idempotency keys.
- Monitor failed authorization and outcome-report requests. Do not retry a
  provider side effect just because its report failed.

The first authorization decision must be recorded before service execution
continues. A failed external outcome write returns an error. This does not
make provider delivery and audit recording one atomic transaction.

## Scope And Compatibility

Custom tools execute outside the Go gateway and report caller-attested
outcomes. Nomos cannot prevent a trusted backend from bypassing its own
wrapper; it is not a host sandbox.

Existing MCP, launcher, identity, and built-in executor interfaces remain
for compatibility. Their presence does not establish a hardened runtime.
This repository no longer provides a standalone coding-agent job runner
or broad enterprise deployment guides. It does not ship Kubernetes
manifests, Helm charts, or a managed platform.

Read [approval authentication](approvals.md),
[security scope](assurance-levels.md), and the
[threat model](threat-model.md) before using real credentials.
