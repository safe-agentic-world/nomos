# Security Review Checklist (M13)

Use this checklist before release.

## Identity And Transport

- [ ] OIDC enabled where required with correct `issuer`, `audience`, and trusted public key path.
- [ ] API key/service HMAC credentials rotated and least-privilege scoped.
- [ ] mTLS enabled for sensitive deployments.
- [ ] mTLS client CA bundle validated and current.

## Policy Integrity

- [ ] `policy.verify_signatures` enabled in production.
- [ ] Policy signature and public key files are provisioned read-only.
- [ ] Policy bundle hash and engine version visible in audit logs.

## Abuse Controls

- [ ] `gateway.rate_limit_per_minute` set per environment capacity.
- [ ] `gateway.circuit_breaker_failures` and cooldown tuned to prevent cascade failures.
- [ ] `gateway.concurrency_limit` set to safe service capacity.

## Secrets And Logging

- [ ] Audit sinks configured with redaction-safe destinations.
- [ ] No raw credentials in outputs/logs; only credential lease IDs are surfaced.
- [ ] Audit tamper-evidence chain fields present (`prev_event_hash`, `event_hash`).

## Operational

- [ ] Graceful shutdown behavior validated.
- [ ] Stateless mode used for horizontally scaled deployments.
- [ ] Runbook includes key rotation and incident response contacts.
