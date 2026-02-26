# janus
The zero-trust, policy-driven control plane for autonomous agents.

## Quick Start (M0)

1. Create a config file (see `config.example.json`).
2. Provide a policy bundle path either in config or via `--policy-bundle`.
3. Start the gateway:

```powershell
.\janus serve --config config.example.json --policy-bundle .\policy-bundle.json
```

Notes:
- `policy_bundle_path` is required and Janus will refuse to start without it.
- Identity and environment are injected from config; they are not accepted from action requests.
