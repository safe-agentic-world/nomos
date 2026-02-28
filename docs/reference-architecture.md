# Controlled Runtime Reference Architecture

This document defines the M17 reference architecture for a strong-guarantee Nomos deployment.

## Threat Assumptions

- Agent code may be prompt-influenced, compromised, or actively malicious.
- Agent processes must be treated as untrusted with respect to filesystem, network, process spawning, and credential access.
- The platform operator controls the runtime boundary (CI runner or Kubernetes cluster) and can enforce network, identity, and process isolation outside the Nomos process itself.

## Reference Layout

```text
+---------------------------+        +---------------------------+
| Sample Agent Workload     |        | Operator-Controlled Infra |
|                           |        |                           |
| - no direct secrets       |        | - workload identity       |
| - no direct egress        |        | - network policy / egress |
| - bounded workspace       |        | - service routing / mTLS  |
+-------------+-------------+        +-------------+-------------+
              |                                        |
              | governed action request                |
              v                                        |
        +-----+----------------------------------------+-----+
        |                  Nomos Gateway                     |
        |                                                    |
        | validate -> normalize -> policy -> execute ->      |
        | redact -> audit                                    |
        +-----+------------------------------+---------------+
              |                              |
              | allowed, policy-bound        | audit events
              v                              v
        +-----+------+                +------+------+
        | Executors  |                | Audit Sink  |
        |            |                | (durable)   |
        +------------+                +-------------+
```

## Enforcement Points

1. Runtime isolation:
   The agent workload runs in a separate container or runner boundary with direct network egress denied by default.
   In the K8s reference, this is the `sample-agent` deployment plus the `sample-agent-egress` NetworkPolicy.
2. Identity:
   Workload identity is asserted by the runtime environment, not by agent input.
3. Mediation:
   Governed side effects are routed through Nomos only.
4. Policy:
   Nomos remains deny-by-default and deny-wins.
5. Redaction:
   Nomos redacts before returning output, logging, or auditing.
6. Audit:
   Denied and allowed actions are written to a durable audit sink.

## Verifiable Signals

The M17 `nomos doctor` strong-guarantee mode validates conservative proxy signals for this architecture:

- container sandbox profile
- gateway mTLS
- OIDC workload identity
- durable audit sink
- deployment-bound environment (`ci`, `staging`, or `prod`)

These are intentionally fail-closed readiness checks rather than a full proof of cluster policy correctness.
