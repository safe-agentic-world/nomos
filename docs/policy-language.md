# Policy Language (v1)

Nomos policy bundles are JSON files with deterministic, deny-wins evaluation.

## Bundle Format

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
