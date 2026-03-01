# Redaction Guarantees

This document defines the redaction contract for Nomos.

## Hard Guarantees

Nomos guarantees the following by default:

- authorization-bearing headers are redacted before agent-visible output, logs, and audit persistence
- brokered secret values are never returned directly from `secrets.checkout`; only lease identifiers are returned
- when executor output contains a brokered secret value, Nomos redacts it before returning or summarizing that output
- audit sinks redact payload bytes before persistence

These guarantees apply to the built-in mediation path only.

## Best-Effort Areas

The following remain best-effort:

- arbitrary binary payloads that do not parse as text
- novel secret formats not covered by built-in or operator-configured patterns
- secrets transformed beyond recognizable text signatures
- secrets emitted outside Nomos mediation in unmanaged environments

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
