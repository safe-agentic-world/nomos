# Integration Kit (M11)

This guide covers agent integration for Janus using MCP stdio mode.

## Codex Setup

1. Build Janus:

```powershell
& "C:\Program Files\Go\bin\go.exe" build -o .\bin\janus.exe .\cmd\janus
```

2. Prepare config and bundle:
- `config.example.json` as a base.
- policy bundle JSON file (deny-by-default unless explicitly allowed).

3. Start MCP server:

```powershell
.\bin\janus.exe mcp --config .\config.example.json --policy-bundle .\policies\m1_5_minimal.json
```

4. Configure Codex MCP client to launch the command above over stdio.

## OpenClaw Setup

OpenClaw uses the same MCP stdio contract.

1. Start Janus with:

```powershell
.\bin\janus.exe mcp --config .\config.example.json --policy-bundle .\policies\m1_5_minimal.json
```

2. Register Janus in OpenClaw MCP server config with command `.\bin\janus.exe` and args:
- `mcp`
- `--config`
- `.\config.example.json`
- `--policy-bundle`
- `.\policies\m1_5_minimal.json`

## MCP Runtime UX (M14)

MCP mode keeps stdout protocol-only. Human-readable status/logs are written to stderr.

New flags:
- `--log-level error|warn|info|debug` (default `info`)
- `--log-format text|json` (default `text`)
- `--quiet` (equivalent to error-only; suppresses startup banner)

Default MCP runtime output behavior:
- one ready banner line on stderr after startup
- errors on stderr
- no non-protocol text on stdout

## CLI Ergonomics (M15)

`janus mcp` now supports short aliases and env fallbacks with deterministic precedence.

Short flags:
- `-c` for `--config`
- `-p` for `--policy-bundle`
- `-l` for `--log-level`
- `-q` for `--quiet`

Env fallbacks:
- `JANUS_CONFIG`
- `JANUS_POLICY_BUNDLE`
- `JANUS_LOG_LEVEL`

Precedence:
1. explicit CLI flag
2. environment variable
3. fail closed

Example:

```powershell
janus mcp -c .\config.example.json -p .\policies\m1_5_minimal.json -l info
```

## Doctor Preflight (M16)

Use `janus doctor` before connecting MCP clients to validate configuration and runtime readiness.

Examples:

```powershell
janus doctor -c .\config.example.json
janus doctor -c .\config.example.json --format json
```

Exit codes:
- `0` READY
- `1` NOT_READY
- `2` INTERNAL_ERROR

## MCP Config Examples

### Example: Generic MCP client JSON

```json
{
  "mcpServers": {
    "janus": {
      "command": ".\\bin\\janus.exe",
      "args": [
        "mcp",
        "--config",
        ".\\config.example.json",
        "--policy-bundle",
        ".\\policies\\m1_5_minimal.json"
      ]
    }
  }
}
```

### Example: Strict approvals-enabled config fragment

```json
{
  "approvals": {
    "enabled": true,
    "store_path": ".\\janus-approvals.db",
    "ttl_seconds": 900,
    "webhook_token": "replace-me"
  }
}
```

## Capabilities Explanation

Use `janus.capabilities` to discover what tools are currently available for a principal/agent/environment under loaded policy.

Response fields:
- `enabled_tools`: policy-allowed tools (for example `janus.fs_read`, `janus.exec`).
- `sandbox_modes`: available sandbox mode envelope (`none` or `sandboxed` in current implementation).
- `network_mode`: `deny` or `allowlist` depending on policy-derived capability.
- `output_max_bytes`, `output_max_lines`: output caps returned to the client.
- `approvals_enabled`: whether approval workflow is configured.

The capability envelope is advisory; final authorization is still performed per action with deny-wins semantics.

## Unmanaged Laptop Limitations And Safe Workflows

In unmanaged developer laptops, mediation is best-effort. Janus cannot guarantee that all side effects are forced through the gateway.

Safe workflow recommendations:
1. Keep policy deny-by-default and only allow required actions.
2. Require approvals for high-risk actions (`process.exec`, `net.http_request`, writes/patches in sensitive paths).
3. Use publish-boundary validation (`repo.validate_change_set`) before creating PRs.
4. Keep audit enabled (`stdout` + `sqlite`) and review `action.completed` events.
5. Avoid local direct credentials; pass only lease IDs in policy/executor metadata.

Operational note:
- Stronger enforcement guarantees are expected in controlled runtimes (CI/container/K8s runners).
