package agenthook

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Codex hook contract, verified against openai/codex at commit e72da2b5
// (codex-rs/hooks): the PreToolUse input carries the same fields as Claude
// Code's (session_id, cwd, hook_event_name, permission_mode, tool_name,
// tool_input, tool_use_id), shell commands arrive as tool "Bash" with
// tool_input.command, file edits arrive as tool "apply_patch" whose
// tool_input.command is the patch text, and MCP tools are named
// mcp__<server>__<tool>. A PreToolUse hook may only block: the output
// {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
// "permissionDecisionReason":...}} or exit 2 with a reason on stderr blocks
// the call, while "ask" and a bare "allow" are rejected as unsupported and
// leave the hook without effect. A PermissionRequest hook runs in the
// approval path and may answer {"decision":{"behavior":"allow"|"deny"}} or
// stay silent to let the normal approval flow continue.
const (
	CodexEventPreToolUse        = "PreToolUse"
	CodexEventPermissionRequest = "PermissionRequest"
	CodexToolApplyPatch         = "apply_patch"
	// CodexDefaultMatcher covers shell commands and patches; Write and Edit
	// are the aliases Codex accepts for apply_patch in matchers.
	CodexDefaultMatcher = "Bash|apply_patch|Write|Edit"
	// CodexBypassMode is the permission_mode Codex reports when approvals
	// are disabled (--dangerously-bypass-approvals-and-sandbox).
	CodexBypassMode = "bypassPermissions"

	codexHookCommandMarker = "nomos hook codex"
)

// Codex ask handling in bypass mode.
const (
	AskInBypassDeny        = "deny"
	AskInBypassPassthrough = "passthrough"
)

// MapCodexToolCall translates a Codex tool call into Nomos actions. Shell
// and MCP calls share the Claude Code mapping; apply_patch is mapped to one
// fs.write action per file the patch touches.
func MapCodexToolCall(in Input, opts Options) Mapping {
	if in.ToolName != CodexToolApplyPatch {
		return MapToolCall(in, opts)
	}
	var params map[string]any
	if err := json.Unmarshal(in.ToolInput, &params); err != nil || params == nil {
		params = map[string]any{}
	}
	patch, _ := params["command"].(string)
	if strings.TrimSpace(patch) == "" {
		patch, _ = params["input"].(string)
	}
	paths, err := PatchPaths(patch)
	if err != nil {
		return Mapping{Findings: []Finding{{Kind: FindingUnsupported, Detail: "apply_patch: " + err.Error()}}}
	}
	var m Mapping
	for _, p := range paths {
		part := mapFile("fs.write", p, in, opts)
		m.Actions = append(m.Actions, part.Actions...)
		m.Findings = append(m.Findings, part.Findings...)
	}
	return m
}

// PatchPaths lists every file an apply_patch document adds, updates, moves
// to, or deletes. The format is Codex's own: a "*** Begin Patch" line, then
// "*** Add File: <path>", "*** Update File: <path>" (optionally followed by
// "*** Move to: <path>"), or "*** Delete File: <path>" headers with their
// hunks, and "*** End Patch". A patch without file headers is an error so
// that a malformed patch is never auto-allowed.
func PatchPaths(patch string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(line, prefix) {
				add(strings.TrimPrefix(line, prefix))
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no file headers found in the patch text")
	}
	return out, nil
}

// CodexPreToolUseOutput renders the PreToolUse hook output for Codex. Only a
// deny is expressed; allow and passthrough produce no output so Codex's own
// approval flow continues. An ask cannot be expressed in PreToolUse: when
// the session runs with approvals disabled (permission_mode
// bypassPermissions) nobody could answer it, so it becomes a deny unless
// askInBypass is passthrough; in other modes it is left to the
// PermissionRequest hook and Codex's prompt.
func CodexPreToolUseOutput(res Result, permissionMode, askInBypass string) ([]byte, error) {
	reason := res.Reason
	switch res.Permission {
	case PermissionDeny:
	case PermissionAsk:
		if permissionMode != CodexBypassMode || askInBypass == AskInBypassPassthrough {
			return nil, nil
		}
		reason += " (requires confirmation, and nothing can ask in bypassPermissions mode)"
	default:
		return nil, nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "Nomos: denied"
	}
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            CodexEventPreToolUse,
			"permissionDecision":       PermissionDeny,
			"permissionDecisionReason": reason,
		},
	})
}

// CodexPermissionRequestOutput renders the PermissionRequest hook output:
// a deny or an allow decision, or no output when Nomos wants the user to
// decide (ask) or has no opinion (passthrough).
func CodexPermissionRequestOutput(res Result) ([]byte, error) {
	var behavior string
	switch res.Permission {
	case PermissionDeny:
		behavior = "deny"
	case PermissionAllow:
		behavior = "allow"
	default:
		return nil, nil
	}
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": CodexEventPermissionRequest,
			"decision": map[string]any{
				"behavior": behavior,
				"message":  res.Reason,
			},
		},
	})
}

// CodexHooksSnippet returns the hooks.json document that registers the
// command for PreToolUse and, when requested, PermissionRequest. Only the
// keys Codex accepts are emitted: its parser rejects unknown fields.
func CodexHooksSnippet(command, matcher string, timeoutSeconds int, permissionRequest bool) map[string]any {
	if strings.TrimSpace(matcher) == "" {
		matcher = CodexDefaultMatcher
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultTimeoutSeconds
	}
	entry := func() []any {
		return []any{map[string]any{
			"matcher": matcher,
			"hooks": []any{map[string]any{
				"type":    "command",
				"command": command,
				"timeout": timeoutSeconds,
			}},
		}}
	}
	hooks := map[string]any{CodexEventPreToolUse: entry()}
	if permissionRequest {
		hooks[CodexEventPermissionRequest] = entry()
	}
	return map[string]any{"hooks": hooks}
}

// InstallCodexHooks merges the registration into a Codex hooks.json file
// (project .codex/hooks.json or ~/.codex/hooks.json), creating it when
// needed and leaving other entries untouched. It reports false when every
// requested event already carries a Nomos entry.
func InstallCodexHooks(path, command, matcher string, timeoutSeconds int, permissionRequest bool) (bool, error) {
	if strings.TrimSpace(command) == "" || !strings.Contains(command, codexHookCommandMarker) {
		return false, fmt.Errorf("hook command must invoke %q", codexHookCommandMarker)
	}
	return installHooks(path, codexHookCommandMarker, CodexHooksSnippet(command, matcher, timeoutSeconds, permissionRequest))
}
