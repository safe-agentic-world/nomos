# Janus

**Ship agentic workflows without giving agents root trust.**

Janus is a zero-trust gateway that sits between AI agents and real side effects (files, shell, network, credentials).

It enforces deterministic policy before execution, then redacts and audits results.

If you use Codex, OpenClaw, or custom agents, Janus gives you guardrails without killing speed.

---

## Why This Matters

Most agent setups are still "tool access by prompt."

Janus adds an actual policy boundary:

- Deny-by-default, deny-wins authorization
- Deterministic evaluation and normalization
- Approval gates for risky actions
- Redaction before outputs leave Janus
- Replayable audit trail with trace linkage

---

## What You Get

- **Fast wedge:** works in minutes with MCP (`janus.fs_read` demo)
- **Real control:** policy-gated `fs`, `exec`, `http`, patch/write paths
- **Safer ops:** rate limits, circuit breakers, TLS/mTLS options
- **Auditability:** bundle hash, risk metadata, tamper-evident chain support
- **Portability:** MCP stdio and HTTP gateway (`/action`, `/run`)

---

## 2-Minute Demo

### 1) Build

```powershell
go build -o .\bin\janus.exe .\cmd\janus
```

### 2) Start Janus in MCP mode

```powershell
.\bin\janus.exe mcp `
  --config .\config.example.json `
  --policy-bundle .\policies\m1_5_minimal.json
```

### 3) Register in Codex

```powershell
codex mcp add janus -- `
  .\bin\janus.exe mcp `
  --config .\config.example.json `
  --policy-bundle .\policies\m1_5_minimal.json
```

### 4) Prove policy is real

In Codex, run:

- Allowed: `Use janus.fs_read to read README.md`
- Denied: `Use janus.fs_read to read .env`

You should see:

- `README.md` allowed (capped output)
- `.env` denied (structured `DENIED_POLICY` response)
- audit events emitted for both
- redaction path executed before returning output

---

## Architecture In One Screen

1. Agent sends action request.
2. Janus validates shape and identity.
3. Janus normalizes resource/params deterministically.
4. Policy engine returns `ALLOW` / `DENY` / `REQUIRE_APPROVAL`.
5. Executor runs only if authorized.
6. Output is redacted and audited.

Tracked status: `TASKS.md` (`M0-M13` complete, with scoped `M6` caveat).

---

## Current Feature Set

- Strict validation with unknown-field rejection (except `context.extensions`)
- Identity verification (API key, service signature, OIDC, agent signature)
- Deterministic policy engine (`deny wins`) + `policy test` / `policy explain`
- Executors: `fs.read`, `fs.write`, `repo.apply_patch`, `process.exec`, `net.http_request`
- Approval workflow (sqlite + TTL + webhook/Slack/Teams endpoints)
- Audit sinks (`stdout`, `sqlite/postgres`, `webhook`) + tamper-evident chain hashes
- Safety visibility metadata (risk level, sandbox/network mode, lease IDs, bundle hash)
- Gateway protections (concurrency/rate/circuit limits, optional TLS/mTLS)

---

## Quick Commands

```powershell
go test ./...
.\bin\janus.exe version
.\bin\janus.exe policy test --action .\action.json --bundle .\policies\m1_5_minimal.json
.\bin\janus.exe policy explain --action .\action.json --bundle .\policies\m1_5_minimal.json
.\bin\janus.exe serve --config .\config.example.json --policy-bundle .\policies\m1_5_minimal.json
```

Release metadata build example:

```powershell
go build -ldflags "-X github.com/safe-agentic-world/janus/internal/version.Version=v1.0.0 -X github.com/safe-agentic-world/janus/internal/version.Commit=$(git rev-parse --short HEAD) -X github.com/safe-agentic-world/janus/internal/version.BuildDate=$(Get-Date -AsUTC -Format o)" -o .\bin\janus.exe .\cmd\janus
.\bin\janus.exe version
```

HTTP endpoints in `serve` mode:

- `GET /healthz`
- `GET /version`
- `POST /action`
- `POST /run`
- `POST /approvals/decide`
- `POST /webhooks/approvals`
- `POST /webhooks/slack/approvals`
- `POST /webhooks/teams/approvals`

---

## Integrations

- Codex + OpenClaw setup: `docs/integration-kit.md`
- MCP capability model and workflow notes: `docs/integration-kit.md`
- Unmanaged laptop limitations and safer workflows: `docs/integration-kit.md`

---

## Security And Design Docs

- Threat model: `docs/threat-model.md`
- Security checklist: `docs/security-checklist.md`
- Policy language: `docs/policy-language.md`
- Canonical JSON and hashing: `docs/canonical-json.md`
- Normalization rules: `docs/normalization.md`
- Approval binding model: `docs/approvals.md`
- Audit schema and replay notes: `docs/audit-schema.md`

---

## Deployment

- M12 deployment guide: `docs/deployment-m12.md`
- CI/K8s readiness: `docs/ci-k8s.md`
- Container image: `Dockerfile`
- K8s manifests: `deploy/k8s/`

---

## Project Governance

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Release history: `CHANGELOG.md`

---

## License

`LICENSE`
