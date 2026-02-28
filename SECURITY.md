# Security Policy

## Supported Versions

Nomos is pre-`v1.0.0`. Security fixes are applied to the latest `main` branch state.

## Reporting a Vulnerability

Please do not open public issues for potential vulnerabilities.

Report privately to the maintainers with:

- affected version/commit
- reproduction steps
- impact assessment
- suggested remediation (if available)

Maintainers will acknowledge receipt and coordinate remediation and disclosure timing.

## Security Expectations

- No secret leakage in logs, audit output, or agent-visible responses.
- Deterministic, fail-closed behavior for policy/config errors.
- No trust in agent-supplied identity/environment claims.
