# Redaction Sources

This document lists the redaction sources used by Nomos.

## Built-In Sources

Nomos ships deterministic pattern redaction for:

- `Authorization` and `Proxy-Authorization` headers
- `Cookie` and `Set-Cookie` headers
- `X-Api-Key` and `X-Auth-Token` headers
- bearer tokens
- basic-auth payloads
- AWS access-key style identifiers (`AKIA...`)
- JWT-like tokens
- PEM blocks

## Broker-Aware Source

For `process.exec`, Nomos also redacts exact secret values materialized from credential leases before returning stdout/stderr.

This is separate from regex-based redaction and is tied to:

- lease binding
- executor allowlisted environment keys
- the specific secret values used for that execution

## Operator-Configured Sources

Operators may append additional regex patterns through config.

Guidance:

- prefer explicit, bounded token formats
- avoid overly broad patterns that degrade readability
- test new patterns against the false-positive corpus before rollout

## Determinism

- the same input bytes and the same configured pattern set always produce the same output bytes
- built-in patterns run in stable order
- custom patterns are appended in config order
