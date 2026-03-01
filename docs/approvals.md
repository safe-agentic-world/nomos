# Approval Binding Model

Nomos binds approvals to deterministic targets so approvals cannot be replayed across different inputs.

## Fingerprint

`action_fingerprint = sha256(canonical_json({normalized_action, principal, agent, environment}))`

`normalized_action` includes:
- `schema_version`
- `action_type`
- `resource`
- canonicalized `params`

Any change to normalized inputs (including params) produces a new fingerprint and requires a new approval.

## Scope

Nomos supports two narrowly scoped bindings:
- `fingerprint` (default): a single normalized action.
- `class` (optional): bounded class key currently limited to `action_type_resource`, derived as `<action_type>|<resource>`.

Approvals are never global.

## Resume Flow

1. Policy returns `REQUIRE_APPROVAL`.
2. Nomos persists a pending approval with TTL in sqlite.
3. External approver records `APPROVE` or `DENY` via approval endpoint/webhook.
4. Agent retries the same action with `context.extensions.approval.approval_id`.
5. Nomos recomputes normalized action and fingerprint and only resumes when approval binding matches and TTL is valid.

## Integrations

Nomos provides integration endpoints:
- Generic webhook: `POST /webhooks/approvals` using header `X-Nomos-Webhook-Token` when configured.
- Slack webhook: `POST /webhooks/slack/approvals` using header `X-Nomos-Slack-Token` when configured.
- Teams webhook: `POST /webhooks/teams/approvals` using header `X-Nomos-Teams-Token` when configured.

Slack payload schema:
- `approval_id` (string, required)
- `decision` (string, required)
- `user_id` (string, required)
- `channel_id` (string, required)
- `comment` (string, optional)

Teams payload schema:
- `approval_id` (string, required)
- `decision` (string, required)
- `user_aad_id` (string, required)
- `conversation_id` (string, required)
- `comment` (string, optional)

Unknown fields are rejected for deterministic validation behavior.

## Params Patch (Future)

Approvals may optionally provide a params patch in a future revision. If applied, it creates a new normalized action and fingerprint, which requires approval against that new target.
