# Egress And Identity

This document explains how the M17 reference deployment combines environment controls and Nomos controls.

## Egress Enforcement

The reference deployment assumes:

- agent workloads have default-deny egress
- only Nomos is allowed to reach approved upstream destinations
- Nomos still applies per-action network allowlists before execution

This creates a layered model:

1. Environment blocks direct agent egress.
2. Nomos blocks disallowed governed requests.

## Identity Enforcement

The reference deployment uses workload identity to bind the runtime to an operator-controlled identity source.

For M17, the strong-guarantee readiness signal is OIDC enabled in Nomos config:

- environment asserts identity
- Nomos verifies identity material
- audit records principal, agent, and environment

## Credential Boundaries

- Agents do not receive raw enterprise credentials directly.
- Nomos brokers short-lived lease IDs.
- Credential materialization happens only inside executors and remains subject to redaction before output/logging/audit.

## Why Both Layers Matter

Nomos alone cannot stop an untrusted workload from bypassing mediation if the environment allows unrestricted egress, direct credential access, or unrestricted process escape.

The M17 reference architecture is therefore explicitly a combined control plane:

- environment enforces the outer boundary
- Nomos enforces the inner deterministic authorization boundary
