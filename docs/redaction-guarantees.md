# Redaction Guarantees

This is the canonical redaction model for Nomos. It combines the guarantee contract and source inventory.

## Hard Guarantees

Nomos guarantees the following by default:

- authorization-bearing headers are redacted before agent-visible output, logs, and audit persistence
- brokered secret values are never returned directly from `secrets.checkout`; only lease identifiers are returned
- when executor output contains a brokered secret value, Nomos redacts it before returning or summarizing that output
- audit sinks redact payload bytes before persistence

These guarantees apply to the built-in mediation path only.

## Redaction Sources

Built-in deterministic sources:

- `Authorization` and `Proxy-Authorization` headers
- `Cookie` and `Set-Cookie` headers
- `X-Api-Key` and `X-Auth-Token` headers
- bearer tokens
- basic-auth payloads
- AWS access-key style identifiers (`AKIA...`)
- JWT-like tokens
- PEM blocks

Broker-aware source:

- for `process.exec`, exact secret values materialized from credential leases are redacted before stdout/stderr are returned

Operator-configured sources:

- operators may append additional regex patterns through config
- custom patterns run after built-ins in configured order

## Best-Effort Areas

The following remain best-effort:

- arbitrary binary payloads that do not parse as text
- novel secret formats not covered by built-in or operator-configured patterns
- secrets transformed beyond recognizable text signatures
- secrets emitted outside Nomos mediation in unmanaged environments

## Determinism

- the same input bytes and the same configured pattern set always produce the same output bytes
- built-in patterns run in stable order
- custom patterns are appended in config order

## Scope

The redaction path is measured across:

- agent-visible stdout/stderr or tool output
- HTTP header/body text handled by Nomos
- patch or diff text handled by Nomos
- audit payload fields before persistence

## Operator Expectations

- add org-specific patterns for internal token formats
- treat redaction as defense-in-depth, not a replacement for least privilege
- keep brokered secrets short-lived and executor-bound
