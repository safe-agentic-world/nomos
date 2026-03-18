# Local Rebuild And MCP Commands

## Remove Previous Local Build

```powershell
if (Test-Path "$env:USERPROFILE\go\bin\nomos.exe") { Remove-Item -Force "$env:USERPROFILE\go\bin\nomos.exe" }
```

## Rebuild Local `nomos.exe`

Run from the Nomos repo root:

```powershell
& "C:\Program Files\PowerShell\7\pwsh.exe" -Command "go build -o '$env:USERPROFILE\go\bin\nomos.exe' ./cmd/nomos"
```

## Verify The Local Binary

```powershell
Get-Command nomos | Format-List Source
nomos version
nomos doctor -c C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json
```

Expected:

- `Source` points to `C:\Users\prudh\go\bin\nomos.exe`
- `nomos version` shows a local build such as `+dirty`
- `policy.bundle_parses` and `policy.bundle_hash` pass

## Re-Register Claude Code MCP

```powershell
claude mcp remove nomos-local
claude mcp add --transport stdio --scope local nomos-local -- "$env:USERPROFILE\\go\\bin\\nomos.exe" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json"
claude mcp list
claude mcp get nomos-local
```

This works because:

- the config path is absolute, so the example policy bundle paths still resolve correctly
- `executor.workspace_root` is left empty in `config.example.json`, so Nomos defaults it to the current working directory of the launched process
- when you start Claude in your target repo, that repo becomes the governed workspace

## Start Claude Code

```powershell
claude
```

## Claude Prompts To Run

```text
Use nomos.capabilities and show me the raw JSON result.
```

```text
Use nomos.fs_write to write "This is a dummy text file." into file://workspace/dummy.txt
```

```text
Use only Nomos tools. Run nomos.exec with ["git","status"] in the workspace.
```

```text
Use only Nomos tools. Run nomos.exec with ["git","push","origin","main"] in the workspace.
```

```text
Use only Nomos tools. Send a POST request to resource url://shop.example.com/checkout/cart-123 to purchase the item. Show me the raw Nomos result, including any approval_id or approval_fingerprint fields if approval is required.
```

## Expected Results

- `nomos.capabilities` includes `nomos.exec`
- `nomos.capabilities` includes `nomos.http_request`
- `tool_advertisement_mode` is `mcp_tools_list_static`
- `tool_states.nomos.exec.state` is `allow` or `mixed`
- `tool_states.nomos.http_request.state` is `require_approval`
- `approval_gated_tools` includes `nomos.http_request`
- `approvals_enabled` is `true`
- `nomos.fs_write` succeeds for `file://workspace/dummy.txt`
- `git status` is allowed
- `git push origin main` is denied by policy
- the purchase request returns `REQUIRE_APPROVAL`
- the loaded config is `examples/configs/config.example.json`, which carries the example multi-bundle policy stack directly
