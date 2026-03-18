# Policy Language (v1)

Nomos policy bundles may be authored in JSON or YAML, but Nomos evaluates them through the same deterministic typed representation with deny-wins semantics.

## Bundle Format

JSON:

```json
{
  "version": "v1",
  "rules": [
    {
      "id": "allow-readme",
      "action_type": "fs.read",
      "resource": "file://workspace/README.md",
      "decision": "ALLOW",
      "principals": ["system"],
      "agents": ["nomos"],
      "environments": ["dev"],
      "risk_flags": ["risk.net"],
      "obligations": {}
    }
  ]
}
```

YAML (equivalent):

```yaml
version: v1
rules:
  - id: allow-readme
    action_type: fs.read
    resource: file://workspace/README.md
    decision: ALLOW
    principals: [system]
    agents: [nomos]
    environments: [dev]
    risk_flags: [risk.net]
    obligations: {}
```

## YAML Support

- `.json` bundles keep the existing typed JSON decode path.
- `.yaml` and `.yml` bundles are convenience input formats only.
- YAML is decoded into the same typed Go structs used by JSON decoding.
- Unknown YAML fields are rejected.
- Duplicate YAML keys are rejected deterministically.
- YAML source bytes are not hashed directly.
- Bundle identity is computed after the typed bundle is converted into canonical JSON, so equivalent JSON and YAML bundles produce the same `policy_bundle_hash`.

## Matching Semantics

- `action_type` is an exact string match or `*` for any.
- `resource` uses deterministic glob patterns:
  - `*` matches a single segment.
  - `**` matches multiple segments.
  - `/` is the only separator; backslashes are rejected.
- `principals`, `agents`, `environments` are optional lists:
  - empty list means “any”.
  - `*` matches any.
- `risk_flags` is an optional list of required flags; all must be present.
- `exec_match` is an optional `process.exec` matcher over normalized `argv` tokens:
  - it applies only to `action_type: process.exec` or `action_type: *`
  - `argv_patterns` is an array of token patterns; any matching pattern is sufficient
  - tokens match exactly unless the token is `*` or `**`
  - `*` matches exactly one argv token
  - `**` matches zero or more argv tokens
- `id` is required and must be stable across bundle versions.

## Determinism

- All inputs are normalized before policy evaluation.
- All matching occurs on normalized inputs only.
- Rule order does not affect decisions; deny-wins is always enforced.

## Decision Order (Deny Wins)

1. If any matching rule returns `DENY` → **DENY**
2. Else if any matching rule returns `REQUIRE_APPROVAL` → **REQUIRE_APPROVAL**
3. Else if any matching rule returns `ALLOW` → **ALLOW**
4. Else → **DENY** (default)

## Pattern Examples

1. `file://workspace/README.md`
2. `file://workspace/docs/**`
3. `file://workspace/src/*/main.go`
4. `repo://org/service`
5. `repo://org/*` (single segment wildcard)
6. `url://api.example.com/v1/**`
7. `url://example.com/*/status`
8. `file://workspace/**/config.json`
9. `file://workspace/.github/*`
10. `file://workspace/**/secrets/*`
11. `file://workspace/assets/**`
12. `repo://org/infra`
13. `url://example.com/health`
14. `file://workspace/scripts/*.sh`
15. `file://workspace/logs/**`

## Policy Pack Merge Order (Explicit)

When multiple bundles are supported, they MUST be merged in this explicit order:

1. built-in baseline pack (deny-biased)
2. org/global packs (ordered list)
3. repo pack (optional)
4. environment pack (dev/ci/prod)
5. local overrides (dev only, loud warnings)

Current starter bundles shipped in-repo:
- `policies/safe.{json,yaml}` (secure local development starter with deny-by-rule secret/code file protections)
- `policies/guarded-prod.{json,yaml}` (stricter allowlists and stronger sandbox expectations)
- `policies/unsafe.{json,yaml}` (explicit opt-in)
- `policies/all-fields.example.{json,yaml}` (schema and obligation surface reference bundle)

## Process Exec Matching

Nomos now supports rule-level argv matching for `process.exec` without introducing tool-specific action types.

Rule-level `exec_match` is part of authorization matching.

Executor-side `exec_allowlist` remains an obligation that constrains what an allowed `process.exec` action may actually run.

These are complementary:

- use `exec_match` to express broad allow / narrow deny / approval patterns in policy
- use `exec_allowlist` to bound actual execution at enforcement time

Example:

```yaml
version: v1
rules:
  - id: allow-git
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["git", "**"]
    obligations:
      sandbox_mode: local
      exec_allowlist:
        - ["git"]

  - id: deny-push-main
    action_type: process.exec
    resource: file://workspace/
    decision: DENY
    exec_match:
      argv_patterns:
        - ["git", "push", "**", "main"]
        - ["git", "push", "**", "master"]
```

With deny-wins semantics:

- `git status` matches `allow-git` and can proceed if the obligations permit it
- `git push origin main` matches both rules, but the narrower `DENY` wins

This matching model is generic and works for any CLI with normalized argv tokens.
