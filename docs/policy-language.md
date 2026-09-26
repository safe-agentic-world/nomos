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
  - `program_patterns` optionally narrows the rule to programs started by a
    relative path with a directory component (`./scripts/test.sh`); see
    [Program Path Semantics](#program-path-semantics)
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

## Rate Limits

Rate limits are configured outside policy bundles under `rate_limits` so enforcement can run after normalization and before policy evaluation. This keeps rate limiting additive: it can only reject an action with `RATE_LIMIT_EXCEEDED`; it never turns a policy denial into an allow.

```json
{
  "rate_limits": {
    "enabled": true,
    "evict_after_seconds": 3600,
    "principal_action": [
      {
        "id": "read-per-principal",
        "action_type": "fs.read",
        "burst": 30,
        "refill_per_minute": 60
      }
    ],
    "principal_resource": [
      {
        "id": "write-readme-per-principal",
        "action_type": "fs.write",
        "resource": "file://workspace/README.md",
        "burst": 2,
        "refill_per_minute": 6
      }
    ],
    "global_tool": [
      {
        "id": "global-http-budget",
        "action_type": "net.http_request",
        "burst": 100,
        "refill_per_minute": 300
      }
    ]
  }
}
```

Rule types:

- `principal_action` creates one bucket per `(principal, action_type)`.
- `principal_resource` creates one bucket per `(principal, normalized_resource)`.
- `global_tool` creates one shared bucket per `action_type`.

All matching rate-limit rules apply. If any matching bucket is empty, Nomos fails closed with `Decision: DENY`, `Reason: RATE_LIMIT_EXCEEDED`, an `action.completed` audit classification of `RATE_LIMIT_EXCEEDED`, and `nomos.rate_limits` telemetry counters. Missing `rate_limits` config means no additional service-stage rate limit is applied; policy behavior is unchanged.

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

When multiple bundles are loaded, they should be merged in this explicit order:

1. built-in baseline pack (deny-biased)
2. org/global packs (ordered list)
3. repo pack (optional)
4. environment pack (dev/ci/prod)
5. local overrides (dev only, loud warnings)

Current starter bundles shipped in-repo:
- `examples/policies/safe.{json,yaml}` (secure local development starter with deny-by-rule secret/code file protections)
- `examples/policies/all-fields.example.{json,yaml}` (schema and obligation surface reference bundle)

These shipped bundles are examples and starter packs only.

Nomos does not depend on any specific checked-in bundle at runtime. Operators can provide their own policy bundles and Nomos evaluates them through the same deterministic policy model.

## Multi-Bundle Loading

Nomos now supports loading multiple policy bundles from a single config with deterministic ordered merge.

Config shape:

```json
{
  "policy": {
    "policy_bundle_paths": [
      "./examples/policies/base.yaml",
      "./examples/policies/repo.yaml",
      "./examples/policies/dev.yaml"
    ],
    "policy_bundle_roles": [
      "baseline",
      "repo",
      "env"
    ],
    "verify_signatures": false,
    "signature_paths": [],
    "public_key_path": ""
  }
}
```

Rules:

- use either `policy_bundle_path` or `policy_bundle_paths`, never both
- bundle order is significant and operator-controlled
- `policy_bundle_roles` is optional but recommended for layered configs
- valid `policy_bundle_roles` values are `baseline`, `org`, `repo`, `env`, and `local_override`
- every configured bundle must load successfully or Nomos fails closed
- duplicate rule IDs across bundles are rejected
- the effective merged policy state gets its own deterministic `policy_bundle_hash`
- for multi-bundle loads, explain, doctor, audit, and startup logs expose ordered bundle provenance

Recommended layered profile:

1. `baseline`
2. `org`
3. `repo`
4. `env`
5. `local_override`

`local_override` is intentionally narrow:

- it is only allowed when `identity.environment` is `dev` or `local`
- it is only allowed when `runtime.deployment_mode` is `unmanaged`
- Nomos fails closed if a `local_override` bundle is configured outside those bounds

If signature verification is enabled for multi-bundle configs:

- `signature_paths` must align one-for-one with `policy_bundle_paths`
- each bundle is verified independently before merge

Checked-in examples:

- `examples/configs/config.layered.example.json`
- `examples/configs/config.layered.local-override.example.json`
- `examples/policies/local-override.yaml`

## Process Exec Matching

Nomos now supports rule-level argv matching for `process.exec` without introducing tool-specific action types.

Rule-level `exec_match` is part of authorization matching.

For rules that use `exec_match`, Nomos derives a typed internal exec constraint surface from the matched policy rules and enforces that surface at execution time as defense-in-depth.

This keeps policy as the only authorization source while still letting the executor fail closed if the matched exec shape is not preserved.

### Argv Pattern Semantics

- Patterns are positional and exact-length: `["git", "reset", "--hard"]` matches
  only that three-token argv. Append `"**"` to match any further tokens:
  `["git", "reset", "--hard", "**"]` also matches `git reset --hard HEAD~5`.
  A pattern without a trailing `"**"` that is meant to gate a command family
  is the most common authoring mistake; the default profiles ship both forms.
- `"**"` matches zero or more tokens and may appear anywhere, including first.
- `"*"` matches exactly one token of any value.
- A token containing `*` or `?` is a whole-token wildcard, and `*` also matches
  `/`: `["**", "*.pem", "**"]` matches any argv that carries a `.pem` path in
  any position, such as `cp certs/server.pem /tmp/`. Tokens without wildcard
  characters match exactly.
- A backslash escapes the next character: `'~/\*'` matches only the literal
  token `~/*` (the glob an agent would write to wipe a home directory), not
  `~/.cache/build`; `\?` and `\\` match a literal question mark and
  backslash. A backslash before any other character is an ordinary backslash,
  so `C:\Users` needs no escaping. The default profiles use this to deny
  `rm -rf ~/*` and `rm -rf /*` outright while a delete of some other path
  outside the workspace is left to the hook's boundary check, which asks.
### Program Path Semantics

`argv[0]` is always the program's base name, so `["rm", "**"]` matches
`rm`, `/bin/rm`, and `./bin/rm` alike. The path the program was started by
is kept separately: when it was a relative path with a directory component
(`./scripts/test.sh`, `tools/gen.py`, `scripts/../tools/gen.py`), the
coding-agent hooks clean it (`scripts/test.sh`, `tools/gen.py`), check it
against the workspace boundary like any other path argument, and pass it as
`params.program`. A bare name, an absolute path, and a home reference carry
no program path.

- `program_patterns` is an optional list of whole-token wildcards matched
  against `params.program`; any match is sufficient, and `argv_patterns`
  must also match.
- A rule with `program_patterns` never matches an action without a program
  path, so it cannot apply to `/tmp/evil.sh`, to `evil.sh` found on `PATH`,
  or to a caller that does not set the field (the MCP `run_command` tool
  does not).
- Patterns must be relative: `/...` and `~...` are rejected at load time.
- Deny and approval rules keep matching on the base name, so a workspace
  script named `rm` or a workspace-built `deno eval` is still decided by
  those rules first.

The `safe-dev` profile uses `program_patterns: ["*"]` with
`argv_patterns: [["**"]]` to allow the project's own scripts inside the
workspace; a script outside it asks through the hook's boundary check.

### Flags Are The Policy's Decision

Which flags are dangerous depends on the program (`git push --force` is
not `npm test --silent`), which is exactly what argv patterns express, so
the executor no longer refuses arguments that start with `--` when the
allowing rules carried `exec_match` patterns: those patterns were matched
by the policy and re-checked by the executor as derived
`exec_constraints`, and a flag they admit runs. The refusal stays in
force for the legacy `exec_allowlist` model and for `process.exec` rules
without argv patterns, because nothing else there constrains the
arguments. Deny the flags you fear explicitly, with a wildcard where the
flag takes a value: `["git", "push", "**", "--force*", "**"]`.

### Authoring Lint

`nomos test` prints a `WARN` line (and `warnings` in JSON output) and
`nomos policy explain` adds `bundle_warnings` for each argv pattern that
ends with a flag and has no trailing `"**"`: `["git", "push", "--force"]`
matches only an argv of exactly three tokens, so `git push --force origin
main` slips past it. Append `"**"` to gate the command family, or keep the
exact form deliberately for a fixed invocation such as `["node",
"--version"]`. Warnings never change a decision or fail a suite.

- Matching is over normalized argv tokens only. Shell syntax such as
  variable expansion, command substitution, or redirection never reaches the
  matcher; the MCP `run_command` tool rejects it and the Claude Code hook
  asks for confirmation or denies it.

Legacy `exec_allowlist` remains supported as a compatibility path for older bundles that do not use `exec_match`.

Rules:

- prefer `exec_match` for all new `process.exec` policy authoring
- Nomos MUST NOT parse shell command strings for policy matching
- Nomos MUST match only normalized argv arrays
- a single rule MUST NOT declare both `exec_match` and `exec_allowlist`
- if matched allow / approval rules mix `exec_match` and legacy `exec_allowlist` models for the same action evaluation, Nomos fails closed with `deny_by_exec_model_conflict`
- if `exec_match` is present on matched allow or approval rules, the derived exec constraints are the primary runtime defense check
- if no `exec_match`-derived constraints exist, legacy `exec_allowlist` may still constrain execution for compatibility

Runtime compatibility mode:

- `policy.exec_compatibility_mode: legacy_allowlist_fallback` keeps legacy `exec_allowlist` bundles working during migration
- `policy.exec_compatibility_mode: strict` rejects runtime startup if allow / approval exec rules still depend on legacy `exec_allowlist`

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

Legacy compatibility example:

```yaml
version: v1
rules:
  - id: allow-legacy-echo
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    obligations:
      sandbox_mode: local
      exec_allowlist:
        - ["cmd", "/c", "echo"]
```

This matching model remains generic and works for any CLI with normalized argv tokens.

## MCP Gateway Action Types

Nomos also uses canonical `mcp://...` resources for governed MCP gateway surfaces beyond `tools/call`.

Current action types:

- `mcp.call` -> `mcp://<server>/<tool>`
- `mcp.resource_read` -> `mcp://<server>/resource/<uri>`
- `mcp.prompt_get` -> `mcp://<server>/prompt/<name>`
- `mcp.completion` -> `mcp://<server>/completion/<ref>`
- `mcp.sample` -> `mcp://<server>/sample`

Notes:

- `<server>` is lowercased during normalization.
- resource URIs are normalized as opaque MCP resource identities, so `mcp://retail/resource/note://retail/customer-42` is the canonical policy form.
- prompt names and completion refs are matched exactly after deterministic normalization.
- forwarded tool arguments are validated against upstream `inputSchema` before policy evaluation, then exposed in action params as canonicalized `tool_arguments`.
- `mcp.sample` is intentionally high-friction: if no rule matches, Nomos denies it by default.
- discovery filtering for `tools/list` is conservative by design: it may under-report tools that are not policy-visible for the current principal, but it must never over-report a tool the caller cannot actually invoke.

Example:

```yaml
version: v1
rules:
  - id: allow-retail-resource
    action_type: mcp.resource_read
    resource: mcp://retail/resource/note://retail/customer-42
    decision: ALLOW

  - id: allow-retail-prompt
    action_type: mcp.prompt_get
    resource: mcp://retail/prompt/incident.summary
    decision: ALLOW

  - id: allow-retail-completion
    action_type: mcp.completion
    resource: mcp://retail/completion/ref/prompt/incident.summary
    decision: ALLOW

  - id: require-approval-retail-sampling
    action_type: mcp.sample
    resource: mcp://retail/sample
    decision: REQUIRE_APPROVAL
```

### Matching Forwarded Tool Arguments

Rules can match canonicalized action params with `params_match`. This is most useful for `mcp.call`, where validated upstream arguments are available under `tool_arguments` and their canonical digest is available as `tool_arguments_hash`.

Example:

```yaml
version: v1
rules:
  - id: allow-specific-refund-reason
    action_type: mcp.call
    resource: mcp://retail/refund.request
    decision: ALLOW
    params_match:
      tool_arguments.reason:
        in: ["damaged", "lost"]
      tool_arguments.vip_customer:
        present: false
```

Supported `params_match` conditions:

- bare scalar/object/array values are exact canonical equality checks
- `equals` compares against one canonical value
- `in` compares against a non-empty set of canonical values
- `present` checks whether the canonical params path exists

Paths are dot-separated object keys. Matching uses normalized canonical params, so key order does not matter and approval fingerprints stay aligned with the same action fingerprinting rules.

## Sampling Trust Inversion

`sampling/createMessage` is not just another MCP helper surface.

An upstream MCP server can use sampling to ask the downstream client's LLM to generate text on its behalf. That reverses the usual trust direction: the upstream tool server is now trying to drive the client model.

Nomos treats that as a governed action:

- upstream sampling is evaluated as `mcp.sample`
- default behavior is deny unless policy explicitly allows or approval grants it
- the sampling fingerprint includes the upstream server plus normalized model hints, token limits, stop conditions, and a canonicalized digest of the requested messages

Operators should only allow `mcp.sample` for upstreams they explicitly trust to consume downstream model capacity and context.
