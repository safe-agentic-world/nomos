# TASKS.md
## One-liner

**Nomos — the zero-trust control plane for autonomous agents.**

Nomos is a **model-agnostic, agent-agnostic execution gateway** that:

- mediates agent side effects at the boundary
- enforces deterministic policy, budgets, and circuit breakers
- brokers credentials with least privilege (agents do **not** hold enterprise credentials)
- executes actions inside hardened sandboxes (where applicable)
- produces auditable, replayable traces (tamper-evidence optional after schema stabilizes)
- enables organizations to safely run autonomous systems in CI/K8s and beyond

---

# 🚨 Core Philosophy (READ FIRST)

## The Nomos Contract

**Nomos does not constrain reasoning.  
Nomos strictly governs execution authority, resource usage, and side effects.**

Agents/models are free to:

- reason
- plan
- propose actions
- propose patches
- attempt repairs

Nomos alone controls (when actions route through Nomos):

- filesystem mutation (strong guarantee in sandboxed/mediated modes)
- command execution
- network access
- credential access
- external side effects
- runaway loops (budgets, rate limits, max calls, timeouts)

---

## Zero Trust Principles (Agentic Edition)

Nomos enforces:

- Never trust, always verify
- Least privilege, just-in-time
- Assume breach
- Enforcement at the **side-effect boundary** (not inside the agent)
- Observable-by-default execution (with strict data minimization)

---

## 🧨 Threat Model Lite (MANDATORY)

**Adversaries Nomos must assume exist:**

- a malicious or compromised agent/model
- a buggy agent that loops or over-acts
- a malicious user prompt trying to cause escalation
- a compromised build workspace (files changed underfoot)
- a compromised integration tool output (e.g., tool returns secrets)

**Trusted computing base (TCB) assumptions (v1):**

- Nomos gateway + policy engine binaries are trusted
- Nomos policy bundles are sourced from trusted storage (signing optional until v1 hardening)
- the sandbox runtime and host kernel enforce isolation as configured (in controlled runtimes)
- credential store (e.g., Vault/KMS) is trusted to enforce lease TTL + access policies

**Non-goals (v1):**

- defending against a fully compromised host kernel in the same trust domain
- guaranteeing mediation in unmanaged developer laptops (best-effort only)

---

## 🛡️ Enforcement Guarantees by Environment

Nomos provides **different guarantee levels** depending on deployment.

### Controlled Runtimes (CI, containers, K8s runners, remote dev)

**Strong guarantee**

- all governed side effects MUST flow through Nomos
- sandbox and network controls are enforceable
- credential isolation is enforceable
- identity/environment claims are asserted by the gateway/auth layer (not agents)

### Unmanaged Environments (developer laptops)

**Best-effort mediation**

- Nomos cannot guarantee full mediation
- MUST provide publish/PR boundary validation
- SHOULD provide optional local hooks
- documentation MUST clearly state reduced guarantees

---

## Design Requirements

### Hard Security Rules

- Agents MUST NOT be given direct credentials/access for Nomos-governed side effects.
- Agents NEVER hold long-lived enterprise credentials.
- Enforcement happens in Nomos (gateway/executors), not in prompts.
- All tool-mediated mutations flow through Nomos authorization.
- All actions are auditable and replayable to the defined replay level.
- Sensitive data MUST NOT leak via logs **or action outputs**.
- Policy evaluation MUST be deterministic and side-effect free.
- **Credentials MUST only be materialized inside Nomos executors** (never returned to agents), and MUST be short-lived + bound.

### UX Requirement

> When an action is allowed, the agent must feel unhindered.

Nomos must prefer:

- structured denials with remediation hints
- fast retry loops
- graceful degradation
- policy “explain” tooling for developers/operators

---

# 🎯 North Star Outcomes

## 1) Trust by Default

- policy-gated execution
- bounded autonomy (budgets/limits)
- strong circuit breakers
- deny-by-default with safe starter packs

## 2) Full Auditability

- deterministic traceability per action
- reconstructable action history (Replay Levels)
- tamper-evidence optional after schema stabilizes

## 3) Model / Agent Agnostic

Works with:

- Codex
- Claude Code
- OpenClaw
- custom agents
- human automation

## 4) Production Ready

- container-first
- CI friendly
- K8s friendly
- <2 minute quickstart
- safe defaults

---

# 🧱 Core Architecture (FOUNDATION)

## Primary Primitive: Action

Every request becomes an **Action**.

Examples:

- `fs.read`
- `fs.write`
- `repo.apply_patch`
- `process.exec`
- `net.http_request`
- `secrets.checkout`
- `git.open_mr`
- `ticket.update`

Nomos MUST be extensible to new action types.

---

## Resource Model

Each action targets a **resource URI**.

Examples:

- `file://workspace/src/app.py`
- `repo://org/service`
- `url://api.example.com/v1/foo`
- `secret://vault/github_token`
- `k8s://cluster/ns/deployment/foo`

All resource URIs MUST be normalized before policy evaluation.

---

## Actor Identity

Every request includes verified identity:

- principal (human or service account)
- agent runtime identity (agent software/process identity)
- sub-agent (optional)
- environment claim (dev/ci/prod) asserted by Nomos, not by agents

Identity MUST flow through the entire pipeline.

---

## Mandatory Execution Pipeline (PEP/PDP/Executor)

For every action:

1. Authenticate (verify principal + agent runtime)
2. Validate (schema, size limits, required fields)
3. Normalize (resource + params canonicalization)
4. Derive risk (Nomos-derived risk flags, not agent-supplied)
5. Authorize (PDP: deterministic policy evaluation)
6. Constrain (merge obligations; enforce circuit breakers)
7. Execute (executor + sandbox where applicable)
8. Observe (telemetry)
9. Redact (output redaction + payload minimization)
10. Record (audit event)

---

# ⚖️ Deterministic Policy Semantics (MANDATORY)

Policy evaluation MUST be fully deterministic.

## Determinism Requirements

- same normalized action + same verified identity/env + same policy bundle + same engine version ⇒ same decision
- all matching occurs on **normalized inputs only**
- policy pack merge order MUST be explicit
- evaluation MUST be side-effect free
- policy bundles MUST have a stable identity: `policy_bundle_hash`
- **canonical hashing MUST be stable across languages and OSes** (see Canonical Encoding)

## Canonical Encoding + Hashing (MANDATORY)

All hashes (`policy_bundle_hash`, `params_hash`, `action_fingerprint`, `audit_event_hash` future) MUST use:

- `sha256` over **canonical JSON encoding**
- canonical JSON MUST be stable (e.g., RFC 8785 JSON Canonicalization Scheme) OR implement an equivalent deterministic encoding:
  - stable key ordering
  - no insignificant whitespace
  - normalized number formatting (prefer strings for IDs; avoid floats where possible)
  - explicit UTF-8
- **If anything cannot be canonicalized safely (e.g., floats), it MUST be represented as strings.**

## Precedence Rules (Deny Wins)

Nomos evaluates **all matching rules**.

Decision order:

1. if ANY rule returns `DENY` → **DENY**
2. else if ANY returns `REQUIRE_APPROVAL` → **REQUIRE_APPROVAL**
3. else if ANY returns `ALLOW` → **ALLOW**
4. else → **DENY (default deny)**

This rule is **non-configurable in v1**.

## Obligation Merge Rules (Deterministic)

When multiple rules apply:

- LIMITS → choose most restrictive numeric values (min)
- SANDBOX → choose most restrictive profile by explicit ordering
- NET → choose most restrictive mode (deny > allowlist > open)
- RATE_LIMIT → choose lowest limit
- TAGS → union
- REDACT → union
- OUTPUT_CAPS → choose smallest caps
- EXEC_ALLOWLIST → intersect / choose stricter allowlist rules (deny wins)
- NET_ALLOWLIST → intersect / choose stricter allowlist rules (deny wins)

Conflicts MUST resolve deterministically.

---

## Canonical Error Taxonomy (MVP)

Every executor result MUST map into:

- `DENIED_POLICY`
- `APPROVAL_REQUIRED`
- `VALIDATION_ERROR`
- `NORMALIZATION_ERROR`
- `SANDBOX_VIOLATION`
- `EXEC_TIMEOUT`
- `OUTPUT_LIMIT`
- `UPSTREAM_ERROR`
- `INTERNAL_ERROR`

Additionally, every result MUST include:

- `retryable: true|false`

---

# 📚 Mandatory Spec Docs (WRITE EARLY)

These docs are part of the product.

- `/docs/normalization.md` — resource + path canonicalization; traversal + symlink rules; glob/pattern determinism
- `/docs/policy-language.md` — match semantics; pattern syntax; examples; stable rule IDs
- `/docs/obligations.md` — typed obligations schema; merge rules; test vectors
- `/docs/audit-schema.md` — AuditEvent v1; redaction policy; replay level definitions
- `/docs/threat-model.md` — assumptions; attacker types; non-goals; mitigations
- **NEW:** `/docs/canonical-json.md` — canonical encoding rules; hashing algorithm; test vectors
- **NEW:** `/docs/approvals.md` — approval binding model; TTL; action_fingerprint; idempotency rules

---

# 🗺️ Milestones (Build in Order)

---

## Implementation Status Snapshot (Current)

Legend:
- `[x]` Implemented in code/tests/docs
- `[~]` Implemented with scoped caveats (see note)
- `[ ]` Not implemented

- `[x] M0` Project foundation
- `[x] M1` Action framework core
- `[x] M1.5` Minimal vertical slice
- `[x] M2` Identity and authentication layer
- `[x] M3` Policy engine v1
- `[x] M4` MCP gateway mode
- `[x] M5` Executors v1 + redaction
- `[~] M6` Sandbox runtime
  Note: deterministic sandbox profile selection and policy enforcement are implemented; hard isolation guarantees still depend on deployment/runtime characteristics.
- `[x] M7` Approval workflow
- `[x] M8` Audit log + replay (Level 1)
- `[x] M9` Tamper evidence (optional chain hashes)
- `[x] M10` Safety visibility
- `[x] M11` Integration kit
- `[x] M12` CI / K8s readiness
- `[x] M13` Hardening for v1.0

---

# M0 — Project Foundation (Week 1)

## Repo Scaffold

```text
/cmd/nomos
/internal/gateway
/internal/action
/internal/normalize
/internal/policy
/internal/executor
/internal/audit
/internal/identity
/internal/credentials
/internal/sandbox
/internal/redact
/pkg/sdk
/docs
```

## Tooling

* [x] choose runtime (Go recommended)
* [x] Makefile or justfile
* [x] lint + format
* [x] unit test harness
* [x] minimal README
* [x] `nomos version` prints engine version + build info

## Configuration (MVP)

* [x] config file + env override
* [x] gateway listen/transport
* [x] policy bundle path (required): policy_bundle_path in config and/or CLI flag --policy-bundle <path>. Nomos MUST fail-closed on startup if no policy bundle is provided (from config or flag)
* [x] executor settings
* [x] audit sink
* [x] MCP exposure
* [x] optional upstream routes
* [x] optional approval config

## Mandatory Docs (stubs OK)

* [x] `/docs/threat-model.md` (TCB + attacker list)
* [x] `/docs/audit-schema.md` (AuditEvent skeleton + redaction notes)
* [x] `/docs/canonical-json.md` (hashing + canonicalization skeleton)

**Acceptance**

* [x] project builds
* [x] tests run
* [x] gateway starts with config
* [x] version + build metadata visible

---

# M1 — Action Framework Core (CRITICAL)

## Action Schema (versioned)

Required fields:

* `schema_version`
* `action_id`
* `action_type`
* `resource`
* `params`
* `principal` (verified)
* `agent` (verified runtime identity)
* `environment` (asserted by Nomos)
* `context` (bounded metadata)
* `trace_id`

### NEW: JSON Schemas (MANDATORY)

* [x] `/internal/action/schema/action.v1.json`
* [x] `/internal/policy/schema/decision.v1.json`
* [x] `/internal/policy/schema/obligations.v1.json`
* [x] `/internal/audit/schema/audit_event.v1.json`

Rules:

* `schema_version` is required and must be `v1` (string)
* reject unknown fields by default
* allow extensions only under `context.extensions` (object), versioned

## Action Validation Layer

* [x] schema validation (using the JSON schemas)
* [x] strict size limits (request, params, context)
* [x] required fields
* [x] reject unknown fields by default (except `context.extensions`)
* [x] validate action_id/trace_id formats (opaque strings, max length, charset)

## 🔧 Normalization Spec (REQUIRED)

Create `/docs/normalization.md`.

Must define:

* resource URI grammar + canonicalization per scheme
* canonical file path forms
* traversal prevention
* **hard separation:** PDP normalization is pure; executor does runtime resolution
* symlink escape handling (execution-time safe resolution)
* pattern/glob semantics (deterministic)
* canonical action type names
* canonical exec request shape
* canonical URL normalization (scheme/host casing, default ports, path normalization rules)
* canonical repo URI normalization (org/repo casing rules)

### Required Tests

* [x] traversal attempts rejected
* [x] symlink escapes rejected (TOCTOU-resistant)
* [x] equivalent URIs normalize identically
* [x] glob/pattern matching deterministic across OSes
* [x] normalization is pure (no FS access in PDP normalization step)

## Trace Lifecycle (minimal)

* [x] emit `trace.start`
* [x] emit `trace.end`
* [x] propagate `trace_id`

## NEW: Canonical Hashing Test Vectors (MANDATORY)

* [x] `/docs/canonical-json.md` defines canonicalization rules
* [x] Add golden tests that hash the same struct to same digest across OSes
* [x] `params_hash = sha256(canonical_json(params_normalized))`

**Acceptance**

* [x] invalid actions rejected deterministically
* [x] normalized forms are stable and test-covered
* [x] trace events emitted for accepted requests
* [x] canonical hashing test vectors pass

---

# M1.5 — Minimal Vertical Slice (CODEX-PROOFING, NO BAKED-IN POLICY)

Goal: force end-to-end correctness (MCP → gateway → validate/normalize → policy → execute → redact → audit)
without hardcoding any temporary policy rules into source code.

## Scope

* [x] implement `fs.read` only (no write, no patch, no exec, no net)
* [x] MCP stdio server exposes `nomos.fs_read`
* [x] gateway loads a policy bundle ONLY from an explicit flag/config:
  - CLI flag: `--policy-bundle <path>` (or config equivalent)
  - **If no bundle is provided, Nomos MUST refuse to start** (fail-closed)
* [x] ship a minimal policy bundle file in-repo (not compiled in), e.g.:
  - `/policies/m1_5_minimal.yaml`
  - allows `fs.read` on `file://workspace/README.md` only
  - denies everything else by default
* [x] `nomos policy test --action <json> --bundle <path>` works against the bundle file
* [x] `nomos policy explain --action <json> --bundle <path>` works against the bundle file
* [x] emit audit JSONL for every request (allowed/denied)
* [x] redaction pass invoked on outputs before returning (can be no-op but MUST exist)
* [x] trace lifecycle events emitted (`trace.start`, `trace.end`) and `trace_id` propagated

## Required behaviors (tests)

* [x] starting Nomos without `--policy-bundle` fails with a clear error message
* [x] with `/policies/m1_5_minimal.yaml` loaded:
  - [x] `fs.read file://workspace/README.md` → ALLOW and returns content (capped)
  - [x] `fs.read file://workspace/anything_else` → DENY with structured `DENIED_POLICY`
* [x] audit event is produced for both allowed and denied requests
* [x] output caps are enforced (bytes/lines) for allowed reads
* [x] redaction step runs for allowed reads (even if it performs no changes)
* [x] decisions are deterministic given same inputs + same bundle

## Acceptance

* [x] agent (via MCP) can call `nomos.fs_read` and receive `README.md` content (capped) WHEN launched with the provided bundle file
* [x] denied reads yield a structured `DENIED_POLICY` response (no content leakage)
* [x] audit JSONL events are produced for every request (allow/deny)
* [x] `trace.start` and `trace.end` events are produced with consistent `trace_id`
* [x] `nomos policy test` and `nomos policy explain` operate on the bundle file

---

# M2 — Identity & Authentication Layer

Support:

* [x] API key (dev)
* [x] service identity (HMAC/mTLS stub acceptable; OIDC later)
* [x] verified agent runtime identity (distinct from principal)

Rules:

* principal identity MUST be verified by gateway auth
* agent identity MUST NOT be supplied by the agent payload without verification
* environment claim MUST be derived from deployment/config/auth (not agent input)

**Acceptance**

* [x] every action has verified identity + environment metadata
* [x] identity is included in policy inputs + audit events

---

# M3 — Policy Engine v1 (SHIP EARLY)

## Policy Language (YAML/JSON)

Match on:

* action_type
* resource patterns (defined syntax)
* principal (id, groups/roles)
* agent runtime (id/type)
* environment
* Nomos-derived risk flags

## NEW: Risk Flags (v1 set; deterministic)

Risk flags MUST be computed by Nomos from normalized action + trace counters + config only:

* `risk.exec` (action_type == `process.exec`)
* `risk.net` (action_type == `net.http_request`)
* `risk.write` (action_type in `fs.write`, `repo.apply_patch`)
* `risk.secrets` (action_type == `secrets.checkout`)
* `risk.high_fanout` (trace action count > configured threshold)
* `risk.large_io` (requested output caps near threshold OR request payload near max)

## `/docs/policy-language.md` (MANDATORY)

Must define:

* pattern syntax and escaping rules
* case sensitivity + path separator normalization
* match order (match all rules; deny-wins)
* stable `rule_id` requirement
* examples (at least 15)
* policy pack merge order rules (explicit list below)

## Policy Pack Merge Order (EXPLICIT)

Merge order MUST be explicit and deterministic:

1. built-in baseline pack (compiled into binary; deny-biased)
2. org/global pack(s) (from config, ordered list)
3. repo pack (optional; if enabled)
4. environment pack (dev/ci/prod specific)
5. local overrides (optional; dev only; loud warnings)

If multiple bundles are loaded, the “bundle identity” MUST include the ordered list of their hashes.

## Decision Schema

```json
{
  "decision": "ALLOW | DENY | REQUIRE_APPROVAL",
  "reason_code": "ENUM",
  "message": "...",
  "retry_hint": "...",
  "matched_rule_ids": [],
  "suggested_params_patch": {},
  "obligations": {},
  "policy_bundle_hash": "sha256:..."
}
```

## Built-in Guardrails (non-bypassable)

* [x] max request payload size
* [x] hard timeouts per action_type
* [x] per-trace circuit breakers (max actions, max retries)
* [x] output caps defaults
* [x] deny-by-default for high-risk action_types unless explicitly allowed by policy pack
* [x] baseline secret redaction in audit/log sinks (defense-in-depth)

## Policy Dev UX (CRITICAL)

* [x] `nomos policy test --action <json> --bundle <path>`
* [x] `nomos policy explain --action <json> --bundle <path>` (prints matched rules + obligations)
* [x] include `policy_bundle_hash` and engine version in explain output

## Starter Policy Packs

Ship:

* [x] `safe-dev` (default; denies dangerous by default)
* [x] `guarded-prod` (strict allowlists; sandbox required)
* [x] `unsafe` (explicit opt-in; loud warnings)

**Acceptance**

* [x] deny-wins verified by tests
* [x] policy evaluation deterministic
* [x] policy bundle hash included in decisions
* [x] `safe-dev` prevents common footguns

---

# M4 — MCP Gateway Mode (MAJOR WEDGE)

## MCP Server

* [x] stdio transport
* [x] HTTP transport (later)

## Tool Exposure (MVP)

* [x] `nomos.capabilities`
* [x] `nomos.fs_read`
* [x] `nomos.fs_write`
* [x] `nomos.apply_patch`
* [x] `nomos.exec` (heavily gated)
* [x] `nomos.http_request` (heavily gated)

## Capability Envelope (MVP)

Return policy-derived capabilities for the caller:

* enabled tools
* sandbox modes
* network mode (deny/allowlist/open)
* key limits (timeouts/output caps)
* approval status/config presence

## 🔐 Publish Boundary Validation (EARLY SAFETY BACKSTOP)

Implement safety backstop for unmanaged environments:

* [x] `repo.validate_change_set`
* [x] derive changed paths/diff summary
* [x] policy checks on diff (resource rules apply to affected paths)
* [x] block forbidden changes before publish/PR open

**Acceptance**

* [x] forbidden changes blocked before publish
* [x] works in unmanaged environments
* [x] capabilities differ by principal/agent/environment

---

# M5 — Executors v1 + Redaction (HARD REQUIREMENTS)

## Executor Interface

Executors receive:

* authorized action (normalized)
* merged obligations (typed)

Return:

* structured result
* metadata
* error classification
* `retryable`

## 🔴 Sensitive Data Handling (NON-NEGOTIABLE)

Nomos MUST prevent secret leakage via:

* logs
* stdout/stderr
* tool responses
* patches/diffs
* audit records

### Requirements

* [x] output redaction pass before returning to agent
* [x] sensitive fields flagged and stripped
* [x] secrets never returned raw to agents by default
* [x] audit stores hashes/references by default for sensitive payloads
* [x] allow explicit “secret reveal” only via approvals + policy + scoped UI surface (future)

### NEW: Redaction Sources (v1)

Redaction MUST include, at minimum:

* known credential formats (common API keys, JWTs, PEM blocks)
* auth headers (`Authorization`, `Proxy-Authorization`, cookies if configured)
* values returned by secrets broker (never returned raw by default anyway)
* configurable org regex patterns

Redaction MUST run on:

* stdout/stderr
* HTTP request/response headers (before returning)
* HTTP bodies (best-effort, size-capped; content-type aware if feasible)
* patches/diffs
* audit payloads

## Filesystem Executor

* [x] `fs.read`
* [x] `fs.write`
* [x] `repo.apply_patch`

Enforce:

* [x] workspace root containment
* [x] output caps (bytes/lines)
* [x] path policies
* [x] symlink-safe resolution in executor (TOCTOU-aware)

### NEW: Normalized vs Resolved Resource Fields

* PDP uses `resource_normalized` (pure string canonical form)
* Executor produces `resource_resolved` metadata (e.g., final resolved path) for audit/diagnostics
* `resource_resolved` MUST be redacted/minimized and MUST NOT leak sensitive paths outside workspace

## Process Executor (HEAVILY GUARDED)

### Canonical exec shape (MANDATORY)

```json
{
  "argv": ["cmd", "arg1"],
  "cwd": "...",
  "env_allowlist_keys": []
}
```

NOT raw shell strings.

### Default policy stance

* [x] deny by default in `safe-dev`
* [x] in `guarded-prod`: allowlist commands only + sandbox required
* [x] enforce output caps + wall timeouts + CPU/mem limits via sandbox
* [x] network disabled unless explicitly allowlisted

### NEW: Exec Allowlist Semantics (v1)

Allowlisting MUST be prefix-based on `argv` (no globbing unless deterministic spec exists).
Example: allow `["git"]` and `["go","test"]`, but not arbitrary `bash -c ...`.

## Network Executor (HTTP only; MVP)

* [x] `net.http_request`

Enforce:

* [x] deny by default in `safe-dev`
* [x] allowlist hostnames/domains in obligations
* [x] request/response size caps
* [x] no raw header echoing unless explicitly allowed
* [x] redact auth headers always

### NEW: URL Normalization Requirement

HTTP executor MUST operate on `url_normalized` (host casing, default ports, scheme) and match allowlists against normalized host+port.

## Credential Broker

* [x] short TTL leases
* [x] lease metadata audited (IDs only; never raw values)
* [x] audience/binding to (principal, agent, trace)
* [x] env injection scoped via allowlist
* [x] never log raw secrets

### NEW: Credential Materialization Rules (MANDATORY)

* secrets may only appear inside:

  * in-memory variables in executor
  * sandbox environment variables that are explicitly allowlisted
  * sandbox-mounted secret files if explicitly required (future), always ephemeral
* secrets MUST NEVER be returned in tool responses
* audit logs store secret references/lease IDs only

**Acceptance**

* [x] secrets do not appear in agent-visible outputs in default configs
* [x] exec is not usable without explicit policy allowance
* [x] HTTP requests are host-allowlisted when enabled

---

# M6 — Sandbox Runtime (v0.3+)

Requirements:

* [x] non-root
* [x] workspace isolation
* [x] network off by default
* [x] resource limits (cpu/mem/pids/disk/wall)
* [x] deterministic working dir
* [x] readonly mounts by default (unless explicitly required)

Profiles:

* [x] local (best-effort)
* [x] container (v1 target)
* [x] future microVM (stretch)

**Acceptance**

* [x] exec + fs mutations enforce containment in controlled runtimes
* [x] sandbox profile chosen deterministically from obligations

---

# M7 — Approval Workflow (v0.4)

* [x] sqlite store
* [x] TTL support
* [x] idempotent decisions
* [x] webhook endpoints
* [x] Slack/Teams integration (optional)
* [x] approvals grant narrowly-scoped permission (single action or bounded class)

## NEW: Approval Binding Model (MANDATORY)

Define in `/docs/approvals.md`:

* `action_fingerprint = sha256(canonical_json({normalized_action, principal, agent, environment}))`
* approvals bind to `action_fingerprint` (or explicitly defined bounded class)
* if any normalized input changes → new fingerprint → new approval required
* approvals may optionally provide a **params patch**; if applied, it produces a new normalized action and fingerprint (i.e., a new approval target)

**Acceptance**

* [x] REQUIRE_APPROVAL blocks execution
* [x] approval resumes action with same normalized inputs
* [x] audit linkage intact (approval event ↔ action ↔ trace)

---

# M8 — Audit Log + Replay (v0.5)

## Replay Levels (CLARIFIED)

### Level 1 — Reconstructable (MVP)

Nomos guarantees:

* full timeline of actions and decisions
* normalized inputs stored as hashes (and redacted summaries where safe)
* policy bundle hash + engine version recorded
* executor metadata sufficient to understand what happened without exposing secrets

### Level 2 — Best-effort re-execution (future)

### Level 3 — Deterministic replay (limited cases)

MVP MUST implement Level 1.

## AuditEvent v1 (MANDATORY)

Must include:

* `timestamp`
* `trace_id`
* `action_id`
* `principal`
* `agent`
* `environment`
* `action_type`
* `resource_normalized`
* `params_hash`
* `decision`
* `matched_rule_ids`
* `obligations`
* `duration_ms`
* `result_classification`
* `retryable`
* `policy_bundle_hash`
* `engine_version`

## NEW: Audit Storage Rules (to prevent secret retention)

* store `params_hash` always
* store `params_redacted_summary` optionally (size-capped, redacted)
* store `result_redacted_summary` optionally (size-capped, redacted)
* never store raw secrets or auth headers
* store `executor_metadata` only after redaction + minimization

## Storage

* [x] stdout JSONL
* [x] sqlite/postgres
* [x] optional webhook

**Acceptance**

* [x] reconstructable traces produced
* [x] no secrets in audit by default
* [x] audit schema versioned and documented

---

# M9 — Tamper Evidence (OPTIONAL)

```
event_hash_i = H(event_i || event_hash_{i-1})
```

* [x] chain hashes for audit streams
* [x] keying strategy (future signing)

---

# M10 — Safety Visibility

CLI/logs must show (redacted):

* [x] risk level (derived)
* [x] policy bundle hash + version label
* [x] sandbox mode
* [x] network mode
* [x] credential lease IDs only
* [x] action summary + decision

---

# M11 — Integration Kit

Docs:

* [x] Codex setup
* [x] OpenClaw setup
* [x] MCP config examples
* [x] capabilities explanation
* [x] “unmanaged laptop” limitations and safe workflows

---

# M12 — CI / K8s Readiness

* [x] stateless mode
* [x] HTTP Run API
* [x] container image
* [x] graceful shutdown
* [x] concurrency limits
* [x] horizontal scaling notes

---

# M13 — Hardening for v1.0

* [x] OIDC
* [x] mTLS
* [x] rate limiting
* [x] circuit breakers (per principal/agent/env)
* [x] policy bundle signing + verification
* [x] threat model doc complete (attacks + mitigations)
* [x] security review checklist

---
---

# M14 — MCP Runtime UX (STDIO-SAFE)

## Goal

Improve operator UX when running `nomos mcp` **without breaking MCP stdio transport**.

Nomos MUST remain protocol-correct while clearly indicating readiness.

---

## Requirements

### Startup Banner (stderr only)

When MCP server is fully ready, Nomos MUST emit **exactly one** human-readable line to **stderr**.

Example:

```text
[Nomos] MCP server ready (env=<env>, policy_bundle_hash=<hash>, engine=<version>, pid=<pid>)
```

Rules:

- MUST print once per successful startup  
- MUST write to **stderr only**  
- MUST NOT write non-protocol data to stdout  
- MUST include:
  - `engine_version`
  - `policy_bundle_hash`
  - `environment`
- MUST NOT include secrets  
- MUST pass through redaction

---

### Logging Controls

Add CLI flags:

- `--log-level error|warn|info|debug`
- `--quiet`
- `--log-format text|json`

Defaults:

- log level: `info`
- format: `text`
- MCP default output: **banner + errors only**

#### Quiet Mode

`--quiet` MUST:

- suppress the startup banner  
- suppress info/warn logs  
- still emit errors  

Equivalent to `--log-level=error`.

---

### Debug Safety

When `--log-level=debug`, Nomos MAY log summaries but MUST NEVER log:

- raw secrets  
- credential material  
- unredacted headers  
- unredacted tool output  

All logs MUST pass through redaction.

---

## Out of Scope

M14 MUST NOT modify:

- MCP protocol behavior  
- policy semantics  
- executor logic  
- audit schema  

---

## Acceptance

- [ ] MCP tools continue to work with Codex/OpenClaw  
- [ ] stdout contains **only MCP protocol bytes**  
- [ ] exactly one banner line appears on stderr (default)  
- [ ] `--quiet` suppresses banner  
- [ ] logs contain no secrets  
- [ ] tests verify stdout/stderr separation  

---

## Implementation Notes

- NEVER print human text to stdout in MCP mode  
- route logs via stderr writer  
- keep default output minimal  
- emit banner only after MCP server is ready  

---

# M15 — CLI Ergonomics (Flags, Env, Invocation)

## Goal

Improve developer ergonomics when invoking Nomos while preserving deterministic, fail-closed behavior.

This milestone adds:

- short flag aliases  
- environment variable fallbacks  
- PATH-safe invocation guarantees  

No runtime semantics may change.

---

## Requirements

### Short Flag Support

Nomos MUST support both long and short forms:

| Purpose | Long | Short |
|--------|------|-------|
| config | `--config` | `-c` |
| policy bundle | `--policy-bundle` | `-p` |
| log level | `--log-level` | `-l` |
| quiet | `--quiet` | `-q` |

Rules:

- short flags MUST behave identically to long flags  
- long flags remain canonical  
- parsing MUST be deterministic  
- help output MUST display both forms  

Example:

```text
nomos mcp -c config.json -p policies/safe-dev.json
```

---

### Environment Variable Fallbacks

If required flags are absent, Nomos MUST consult environment variables.

Support:

| Setting | Env |
|--------|-----|
| config | `NOMOS_CONFIG` |
| policy bundle | `NOMOS_POLICY_BUNDLE` |
| log level | `NOMOS_LOG_LEVEL` |

Precedence (highest → lowest):

1. explicit CLI flag  
2. environment variable  
3. fail closed  

Rules:

- MUST remain deterministic  
- MUST fail closed if policy bundle unresolved  
- MUST NOT silently infer security-critical values  
- resolved source SHOULD be visible at debug level  

---

### Invocation Robustness

Nomos binary MUST work correctly when invoked as:

```text
nomos mcp ...
```

Requirements:

- no working-directory assumptions  
- version command works from any directory  
- relative paths resolved deterministically  
- error messages include actionable guidance  

---

### Help Text Quality

Improve:

- `nomos --help`  
- `nomos mcp --help`

Help MUST:

- show short + long flags  
- remain concise  
- include one minimal example  
- remain deterministic across runs  

---

## Out of Scope

M15 MUST NOT change:

- MCP protocol behavior  
- policy semantics  
- executor behavior  
- audit schema  
- security guarantees  

This milestone is **CLI UX only**.

---

## Acceptance

- [ ] short flags behave identically to long flags  
- [ ] env fallback works as specified  
- [ ] precedence rules enforced deterministically  
- [ ] Nomos fails closed if bundle missing  
- [ ] `nomos mcp -c ... -p ...` works  
- [ ] binary runs correctly from any directory  
- [ ] help output shows short flags  
- [ ] tests cover flag/env precedence  

---

## Tests (MANDATORY)

Add tests for:

- [ ] short vs long flag equivalence  
- [ ] environment fallback behavior  
- [ ] precedence ordering  
- [ ] missing bundle still fails closed  
- [ ] help output stability  

---

## Implementation Notes

- prefer existing CLI framework  
- avoid implicit defaults for security inputs  
- keep help output stable for docs/tests  
- do not weaken fail-closed startup behavior  

---

# M16 — Doctor Command (Deterministic Preflight)

## Goal

Provide a deterministic preflight command that validates Nomos configuration and runtime readiness **before** agents connect.

This reduces misconfiguration, improves first-run success, and strengthens operator confidence.

The doctor command MUST be read-only and side-effect free.

---

## Command

Add a new top-level command:

```text
nomos doctor
```

Purpose:

- validate configuration
- validate policy bundle
- validate runtime prerequisites
- surface actionable diagnostics

Doctor MUST NOT start MCP or HTTP servers.

---

## Checks (MVP)

Doctor MUST perform the following deterministic checks.

### Configuration

- [ ] config file loads successfully
- [ ] required fields present
- [ ] environment is recognized
- [ ] paths resolve deterministically

Failures MUST be reported with clear remediation hints.

---

### Policy Bundle

- [ ] bundle path exists
- [ ] bundle parses successfully
- [ ] rules compile deterministically
- [ ] policy bundle hash computed
- [ ] deny-by-default posture verified

Doctor MUST NOT silently succeed if bundle missing.

---

### Identity Layer

- [ ] configured auth mode is valid
- [ ] required keys/secrets present (existence only; never print values)
- [ ] environment claim derivation valid

Doctor MUST NOT materialize credentials.

---

### MCP Readiness (static checks only)

- [ ] MCP mode enabled in config
- [ ] required transports configured
- [ ] stdio mode structurally valid

Doctor MUST NOT open stdio loop.

---

### Filesystem Safety

- [ ] workspace root exists (if configured)
- [ ] workspace path canonicalizes correctly
- [ ] no obvious misconfiguration (e.g., empty root)

No filesystem mutation allowed.

---

## Output Requirements

### Default (human)

Doctor prints a concise report to stdout:

Example structure:

```text
Nomos Doctor Report

[PASS] config loaded
[PASS] policy bundle parsed (hash=sha256:...)
[PASS] identity configuration valid
[PASS] MCP configuration valid

Result: READY
```

---

### JSON Mode

Support:

```text
nomos doctor --format json
```

JSON MUST be deterministic and include:

- overall_status
- checks[]
- policy_bundle_hash (if available)
- engine_version

---

## Exit Codes

Doctor MUST use deterministic exit codes:

- `0` → READY
- `1` → NOT READY
- `2` → INTERNAL ERROR

This enables CI usage.

---

## Safety Requirements

Doctor MUST:

- be read-only
- be side-effect free
- never emit secrets
- pass all output through redaction where applicable
- be deterministic given same inputs

Doctor MUST NOT:

- contact external services
- start MCP server
- execute actions
- materialize credentials

---

## Out of Scope

M16 MUST NOT modify:

- policy engine behavior
- executor behavior
- MCP runtime
- audit pipeline
- approval flow

---

## Acceptance

- [ ] `nomos doctor` runs without starting servers
- [ ] failures produce actionable messages
- [ ] JSON mode works deterministically
- [ ] exit codes follow spec
- [ ] no secrets appear in output
- [ ] tests cover ready and not-ready states

---

## Tests (MANDATORY)

Add tests for:

- [ ] valid config → READY
- [ ] missing bundle → NOT READY
- [ ] malformed bundle → NOT READY
- [ ] JSON output deterministic
- [ ] exit codes correct
- [ ] output passes redaction

---

## Implementation Notes

- reuse existing config/policy loaders
- avoid duplicate validation logic
- keep output stable for CI usage
- prefer deterministic ordering of checks
- keep runtime fast (<200ms target)

---
---

# 🚀 Why this is the right M16

This milestone gives you **massive leverage**:

✅ reduces user setup failures
✅ improves enterprise confidence
✅ enables CI gating
✅ matches tools like kubectl/terraform
✅ zero risk to security model
✅ very GitHub-visible polish

---

# ✅ Definition of Done (v1)

Nomos v1 must:

* mediate agent tool actions via MCP and HTTP
* enforce deterministic policy with deny-wins and typed obligations
* broker credentials safely with short TTL + bindings
* constrain execution via sandbox profiles
* support approvals with narrow scope + TTL
* produce reconstructable (Level 1) audit traces with no secret leakage by default
* run in CI/K8s with safe defaults
* remain model/agent agnostic

---

# 🏁 Final Positioning

**Nomos is not another agent.**

Nomos is:

> **the zero-trust control plane for agentic systems**

It brings:

* governance
* bounded autonomy
* auditability
* credential safety
* enterprise trust

to any model, agent, or workflow.
