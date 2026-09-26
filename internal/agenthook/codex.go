package agenthook

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
)

// Codex hook contract, verified against openai/codex at commit e72da2b5
// (codex-rs/hooks): the PreToolUse input carries the same fields as Claude
// Code's (session_id, cwd, hook_event_name, permission_mode, tool_name,
// tool_input, tool_use_id) plus turn_id; shell commands arrive as tool
// "Bash" with tool_input.command, file edits as tool "apply_patch" whose
// tool_input.command is the patch text, and MCP tools as
// mcp__<server>__<tool>. A PreToolUse hook may only block: the output
// {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
// "permissionDecisionReason":...}} or exit 2 with a reason on stderr blocks
// the call, while "ask" and a bare "allow" are rejected as unsupported and
// leave the hook without effect. A PermissionRequest hook runs in the
// approval path, before Codex's own reviewer or the user, and may answer
// {"decision":{"behavior":"allow"|"deny"}} or stay silent. The approvals it
// sees include escalations (a retry outside the sandbox after a denial, a
// network grant, a command the model marked as needing escalated
// permissions), and a retry without a model justification is
// payload-identical to a plain prompt, so an allow there could remove a
// sandbox rather than a prompt. Nomos therefore only ever answers deny.
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
	// CodexDefaultMode is the permission_mode Codex reports for every other
	// approval policy; in its usual on-request policy a command the hook
	// does not block runs inside the sandbox without a prompt.
	CodexDefaultMode = "default"

	codexHookCommandMarker = "nomos hook codex"
)

// Codex ask handling for PreToolUse, which cannot express an ask.
const (
	AskDeny        = "deny"
	AskPassthrough = "passthrough"
)

// CodexOptions tunes how Nomos decisions are expressed to Codex.
type CodexOptions struct {
	// Ask is what a Nomos ask becomes in PreToolUse: AskDeny (fail closed,
	// the default) or AskPassthrough (Codex's own flow, which in default
	// mode means a sandboxed run with no prompt).
	Ask string
}

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
		m.merge(mapFile("fs.write", p, in, opts))
	}
	return m
}

// Codex patch markers (codex-rs/apply-patch/src/parser.rs).
const (
	patchBegin       = "*** Begin Patch"
	patchEnd         = "*** End Patch"
	patchAddFile     = "*** Add File: "
	patchUpdateFile  = "*** Update File: "
	patchDeleteFile  = "*** Delete File: "
	patchMoveTo      = "*** Move to: "
	patchEndOfFile   = "*** End of File"
	patchEnvironment = "*** Environment ID: "
)

// PatchPaths lists every file an apply_patch document adds, updates,
// moves to, or deletes, following Codex's own streaming parser: outside an
// update hunk every line is trimmed of surrounding whitespace before the
// markers are matched, so an indented "*** Add File:" is a header, not
// content; inside an update hunk only trailing whitespace is trimmed, so
// an indented marker there is a context line. Any other line that starts
// with "***" after trimming, a patch without file headers, and a "Move to"
// outside an update hunk are errors, so a document the parser does not
// fully understand is never auto-allowed.
func PatchPaths(patch string) ([]string, error) {
	const (
		stateStart = iota
		stateAdd
		stateUpdate
		stateDelete
	)
	state := stateStart
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	lines := strings.Split(patch, "\n")
	for i, line := range lines {
		var t string
		if state == stateUpdate {
			t = strings.TrimRight(line, " \t\r\v\f")
		} else {
			t = strings.TrimSpace(line)
		}
		switch {
		case t == patchBegin || t == patchEnd || t == patchEndOfFile:
			continue
		case strings.HasPrefix(t, patchEnvironment):
			continue
		case strings.HasPrefix(t, patchAddFile):
			state = stateAdd
			add(strings.TrimSpace(strings.TrimPrefix(t, patchAddFile)))
		case strings.HasPrefix(t, patchUpdateFile):
			state = stateUpdate
			add(strings.TrimSpace(strings.TrimPrefix(t, patchUpdateFile)))
		case strings.HasPrefix(t, patchDeleteFile):
			state = stateDelete
			add(strings.TrimSpace(strings.TrimPrefix(t, patchDeleteFile)))
		case strings.HasPrefix(t, patchMoveTo):
			if state != stateUpdate {
				return nil, fmt.Errorf("line %d: \"*** Move to:\" outside an update hunk", i+1)
			}
			add(strings.TrimSpace(strings.TrimPrefix(t, patchMoveTo)))
		case strings.HasPrefix(t, "***"):
			return nil, fmt.Errorf("line %d: unrecognized patch marker %q", i+1, truncate(t))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no file headers found in the patch text")
	}
	return out, nil
}

// CodexWire is what the adapter sends back to Codex for one event.
type CodexWire struct {
	// Decision is "deny", "allow", or "" when nothing is printed.
	Decision string
	Output   []byte
}

// CodexPreToolUseOutput renders the PreToolUse hook output. Only a deny is
// expressed; allow and passthrough print nothing so Codex's own flow
// continues. An ask cannot be expressed here, so it becomes a deny (the
// default) or nothing (AskPassthrough); the reason says which.
func CodexPreToolUseOutput(res Result, permissionMode string, opts CodexOptions) (CodexWire, error) {
	reason := res.Reason
	switch res.Permission {
	case PermissionDeny:
	case PermissionAsk:
		if opts.Ask == AskPassthrough {
			return CodexWire{}, nil
		}
		if permissionMode == CodexBypassMode {
			reason += " (requires confirmation, and nothing can ask while approvals are disabled)"
		} else {
			reason += " (requires confirmation, which Codex's PreToolUse hook cannot request)"
		}
	default:
		return CodexWire{}, nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "Nomos: denied"
	}
	out, err := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            CodexEventPreToolUse,
			"permissionDecision":       PermissionDeny,
			"permissionDecisionReason": reason,
		},
	})
	return CodexWire{Decision: PermissionDeny, Output: out}, err
}

// CodexPermissionRequestOutput renders the PermissionRequest hook output.
// A Nomos deny is answered as a deny. Everything else prints nothing, which
// leaves the decision to Codex's reviewer or the user: an allow is never
// answered, because the approvals Codex routes here include retries after
// a sandbox denial that are indistinguishable from a plain prompt, and an
// allow there would remove the sandbox rather than the prompt.
func CodexPermissionRequestOutput(res Result) (CodexWire, error) {
	if res.Permission != PermissionDeny {
		return CodexWire{}, nil
	}
	out, err := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": CodexEventPermissionRequest,
			"decision": map[string]any{
				"behavior": PermissionDeny,
				"message":  res.Reason,
			},
		},
	})
	return CodexWire{Decision: PermissionDeny, Output: out}, err
}

// CodexAuditEvents returns the audit records for one Codex hook event,
// annotated with what was sent back to Codex (wire_decision: deny, allow,
// or none) and the adapter settings that shaped it, so the file shows what
// Codex received and not only the pre-translation permission.
func CodexAuditEvents(in Input, res Result, wire CodexWire, copts CodexOptions, opts Options, now time.Time) []audit.Event {
	events := AuditEvents(in, res, opts, now)
	decision := wire.Decision
	if decision == "" {
		decision = "none"
	}
	askMode := copts.Ask
	if askMode == "" {
		askMode = AskDeny
	}
	for i := range events {
		md := events[i].ExecutorMetadata
		md["wire_decision"] = decision
		md["ask_mode"] = askMode
		md["outside_workspace"] = opts.OutsideWorkspace
	}
	return events
}

// CodexMatcher returns the hooks.json matcher for the tools Nomos decides.
// Codex reads a matcher made only of letters, digits, "_" and "|" as exact
// alternatives and anything else as an unanchored regular expression, so
// adding the mcp__ pattern to the default list is done inside anchors:
// otherwise "Edit" would also match every future tool whose name contains
// it. A matcher that is already a regular expression gets an anchored
// alternative appended.
func CodexMatcher(matcher string, includeMCP bool) string {
	matcher = strings.TrimSpace(matcher)
	if matcher == "" {
		matcher = CodexDefaultMatcher
	}
	if !includeMCP || strings.Contains(matcher, "mcp__") {
		return matcher
	}
	if isCodexExactMatcher(matcher) {
		return "^(" + matcher + "|mcp__.*)$"
	}
	return matcher + "|^mcp__.*$"
}

func isCodexExactMatcher(matcher string) bool {
	for _, r := range matcher {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '|':
		default:
			return false
		}
	}
	return true
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

// codexHookEvents are the lifecycle events Codex's hooks.json accepts
// (codex-rs/config/src/hook_config.rs).
var codexHookEvents = map[string]bool{
	"PreToolUse": true, "PermissionRequest": true, "PostToolUse": true, "PreCompact": true, "PostCompact": true,
	"SessionStart": true, "SessionEnd": true, "UserPromptSubmit": true, "SubagentStart": true, "SubagentStop": true,
	"Stop": true, "Interrupt": true,
}

// InstallCodexHooks merges the registration into a Codex hooks.json file
// (project .codex/hooks.json or ~/.codex/hooks.json), creating it when
// needed and leaving other entries untouched. It reports false when every
// requested event already carries a Nomos entry, and refuses a file whose
// top-level keys or event names Codex would reject, because Codex drops
// such a file entirely and the hook would silently never run.
func InstallCodexHooks(path, command, matcher string, timeoutSeconds int, permissionRequest bool) (bool, error) {
	if strings.TrimSpace(command) == "" || !strings.Contains(command, codexHookCommandMarker) {
		return false, fmt.Errorf("hook command must invoke %q", codexHookCommandMarker)
	}
	validate := func(doc map[string]any) error {
		for key := range doc {
			if key != "hooks" && key != "description" {
				return fmt.Errorf("hooks.json carries the top-level key %q, which Codex rejects (it would ignore the whole file); remove it first", key)
			}
		}
		if hooks, ok := doc["hooks"].(map[string]any); ok {
			for event := range hooks {
				if !codexHookEvents[event] {
					return fmt.Errorf("hooks.json carries the event %q, which Codex rejects (it would ignore the whole file); remove it first", event)
				}
			}
		}
		return nil
	}
	return installHooksValidated(path, codexHookCommandMarker, CodexHooksSnippet(command, matcher, timeoutSeconds, permissionRequest), validate)
}
