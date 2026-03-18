# Policy Explain

This document defines the `nomos policy explain` output contract.

## Purpose

`nomos policy explain` provides deterministic, operator-safe denial context without exposing raw secrets or sensitive policy internals.

## Output Fields

- `decision`
- `reason_code`
- `matched_rule_ids`
- `policy_bundle_hash`
- `policy_bundle_sources` (multi-bundle only)
- `engine_version`
- `assurance_level`
- `obligations_preview`

For non-allow outcomes, Nomos also emits:

- `why_denied`
- `minimal_allowing_change` (unless disabled by config)

## why_denied

`why_denied` contains:

- `reason_code`: the top-level denial reason
- `deny_rules`: the deny rule IDs that caused a deny-wins outcome
- `matched_conditions`: a safe, boolean-only summary
- `remediation_hint`: a deterministic human-readable hint

`deny_rules` entries contain:

- `rule_id`
- `reason_code`
- `matched_conditions`
- `bundle_source` (multi-bundle only)

`policy_bundle_sources` is emitted only when Nomos evaluated a merged multi-bundle policy set.

It preserves the ordered bundle provenance as `path#hash` labels so operators can identify which inputs produced the effective merged policy state.

The matched-condition view is intentionally limited to booleans. It does not echo request params, headers, tokens, or other raw inputs.

## obligations_preview

`obligations_preview` shows the merged obligations that would apply on the applicable non-deny path:

- for `ALLOW`, the merged allow obligations
- for `REQUIRE_APPROVAL`, the merged approval obligations
- for `DENY`, the merged allow obligations that would apply if the deny outcome were removed, if any

## minimal_allowing_change

This field is a deterministic remediation suggestion.

Rules:

- derived from normalized action shape and policy outcome only
- safe to expose in CI logs
- may be disabled via `policy.explain_suggestions: false`

## Stability

- field set is deterministic for the same inputs
- map content is stable under Go's JSON encoding rules
- output must remain safe for CI assertions
