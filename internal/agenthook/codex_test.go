package agenthook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/launcher"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestPatchPathsListsEveryFileHeader(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: docs/new.md\n+hello\n*** Update File: src/main.go\n*** Move to: src/app.go\n@@\n-a\n+b\n*** Delete File: old.txt\n*** Update File: src/main.go\n*** End Patch\n"
	paths, err := PatchPaths(patch)
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	want := []string{"docs/new.md", "src/main.go", "src/app.go", "old.txt"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if _, err := PatchPaths("*** Begin Patch\n*** End Patch\n"); err == nil {
		t.Fatalf("a patch without file headers must be an error")
	}
	if _, err := PatchPaths("not a patch"); err == nil {
		t.Fatalf("free text must be an error")
	}
	// Codex trims every line outside an update hunk before matching the
	// markers, so an indented header is a header and must be listed.
	indented := "*** Begin Patch\n   *** Add File: config/.env\n+SECRET=1\n\t*** Delete File: keep.txt\n*** End Patch"
	paths, err = PatchPaths(indented)
	if err != nil || strings.Join(paths, ",") != "config/.env,keep.txt" {
		t.Fatalf("indented headers: %v err=%v", paths, err)
	}
	// Inside an update hunk only trailing whitespace is trimmed: an
	// indented marker there is content, and the real header still counts.
	inHunk := "*** Begin Patch\n*** Update File: notes.md\n@@\n-a\n+   *** Add File: ../escape.txt\n*** Add File: real.txt\n+x\n*** End Patch"
	paths, err = PatchPaths(inHunk)
	if err != nil || strings.Join(paths, ",") != "notes.md,real.txt" {
		t.Fatalf("marker inside a hunk: %v err=%v", paths, err)
	}
	// Anything else that looks like a marker, and a Move outside an update
	// hunk, is an error rather than a silently ignored line.
	for _, bad := range []string{
		"*** Begin Patch\n*** Add File: a.txt\n+x\n*** Rename File: b.txt\n*** End Patch",
		"*** Begin Patch\n*** Add File: a.txt\n*** Move to: b.txt\n+x\n*** End Patch",
		"*** Begin Patch\n*** Move to: b.txt\n*** End Patch",
	} {
		if _, err := PatchPaths(bad); err == nil {
			t.Fatalf("must be an error: %q", bad)
		}
	}
	// An Environment ID line is accepted, and "*** End of File" is not a path.
	paths, err = PatchPaths("*** Begin Patch\n*** Environment ID: env-1\n*** Update File: a.txt\n@@\n-a\n+b\n*** End of File\n*** End Patch")
	if err != nil || strings.Join(paths, ",") != "a.txt" {
		t.Fatalf("environment id: %v err=%v", paths, err)
	}
}

func TestMapCodexToolCallMapsPatchesSecretsAndEscapes(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	// Bash goes through the shared shell mapping.
	res, err := EvaluateMapping(engine, toolInput(root, "Bash", map[string]any{"command": "cat config/.env"}), MapCodexToolCall(toolInput(root, "Bash", map[string]any{"command": "cat config/.env"}), opts), opts)
	if err != nil || res.Permission != PermissionDeny {
		t.Fatalf("bash secret read: %s %q err=%v", res.Permission, res.Reason, err)
	}
	// apply_patch maps to one fs.write per touched file.
	patch := "*** Begin Patch\n*** Update File: src/main.go\n@@\n-a\n+b\n*** Add File: src/new.go\n+package x\n*** End Patch"
	in := toolInput(root, CodexToolApplyPatch, map[string]any{"command": patch})
	m := MapCodexToolCall(in, opts)
	if len(m.Actions) != 2 || m.Actions[0].ActionType != "fs.write" || m.Actions[0].Resource != "file://workspace/src/main.go" || m.Actions[1].Resource != "file://workspace/src/new.go" {
		t.Fatalf("patch mapping: %+v", m.Actions)
	}
	res, err = EvaluateMapping(engine, in, m, opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("workspace patch must be allowed: %s %q err=%v", res.Permission, res.Reason, err)
	}
	// A patch that reaches outside the workspace is flagged.
	escape := toolInput(root, CodexToolApplyPatch, map[string]any{"command": "*** Begin Patch\n*** Add File: ../outside.txt\n+x\n*** End Patch"})
	res, err = EvaluateMapping(engine, escape, MapCodexToolCall(escape, opts), opts)
	if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
		t.Fatalf("escaping patch: %s %q err=%v", res.Permission, res.Reason, err)
	}
	// With --outside-workspace passthrough, a patch that touches both a
	// workspace file and an escaping file is left to Codex as a whole; the
	// allowed part must never decide the call alone.
	pass := opts
	pass.OutsideWorkspace = ModePassthrough
	mixed := toolInput(root, CodexToolApplyPatch, map[string]any{"command": "*** Begin Patch\n*** Update File: src/main.go\n@@\n-a\n+b\n*** Add File: ../outside.txt\n+x\n*** End Patch"})
	res, err = EvaluateMapping(engine, mixed, MapCodexToolCall(mixed, pass), pass)
	if err != nil || !res.Passthrough() {
		t.Fatalf("mixed patch under passthrough must be left to Codex, got %s %q err=%v", res.Permission, res.Reason, err)
	}
	if len(res.Mapping.Findings) != 1 || res.Mapping.Findings[0].Kind != FindingOutsideWorkspace {
		t.Fatalf("the escaping file must be recorded as a finding: %+v", res.Mapping.Findings)
	}
	// A decided workspace file still decides the whole patch under
	// passthrough: safe-dev asks before a secrets file is written, and that
	// ask wins over the deferred escaping file.
	profileBundle, err := launcher.EmbeddedProfileBundle("safe-dev")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	mixedAsk := toolInput(root, CodexToolApplyPatch, map[string]any{"command": "*** Begin Patch\n*** Update File: config/.env\n@@\n-a\n+b\n*** Add File: ../outside.txt\n+x\n*** End Patch"})
	res, err = EvaluateMapping(policy.NewEngine(profileBundle), mixedAsk, MapCodexToolCall(mixedAsk, pass), pass)
	if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "safe-dev-approve-secret-file-write") {
		t.Fatalf("a decided file must win over passthrough: %s %q err=%v", res.Permission, res.Reason, err)
	}
	// A patch without headers is refused rather than allowed.
	bad := toolInput(root, CodexToolApplyPatch, map[string]any{"command": "garbage"})
	res, err = EvaluateMapping(engine, bad, MapCodexToolCall(bad, opts), opts)
	if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "apply_patch") {
		t.Fatalf("malformed patch: %s %q err=%v", res.Permission, res.Reason, err)
	}
	// Unknown Codex tools pass through.
	other := MapCodexToolCall(toolInput(root, "spawn_agent", map[string]any{"prompt": "x"}), opts)
	if !other.Passthrough {
		t.Fatalf("unknown tool must pass through: %+v", other)
	}
}

func TestCodexOutputsFollowTheVerifiedContract(t *testing.T) {
	deny := Result{Permission: PermissionDeny, Reason: "Nomos: profile denies rm"}
	wire, err := CodexPreToolUseOutput(deny, CodexDefaultMode, CodexOptions{})
	if err != nil || wire.Decision != PermissionDeny {
		t.Fatalf("deny: %+v err=%v", wire, err)
	}
	var parsed struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(wire.Output, &parsed); err != nil || parsed.HookSpecificOutput.HookEventName != "PreToolUse" || parsed.HookSpecificOutput.PermissionDecision != "deny" || parsed.HookSpecificOutput.PermissionDecisionReason != "Nomos: profile denies rm" {
		t.Fatalf("deny wire: %s err=%v", wire.Output, err)
	}
	var generic map[string]any
	_ = json.Unmarshal(wire.Output, &generic)
	if len(generic) != 1 {
		t.Fatalf("PreToolUse output must carry only hookSpecificOutput (Codex rejects unknown fields): %s", wire.Output)
	}

	// PreToolUse cannot ask, so an ask is a deny in every mode by default.
	ask := Result{Permission: PermissionAsk, Reason: "Nomos: requires confirmation"}
	wire, err = CodexPreToolUseOutput(ask, CodexDefaultMode, CodexOptions{})
	if err != nil || wire.Decision != PermissionDeny || !strings.Contains(string(wire.Output), "PreToolUse hook cannot request") {
		t.Fatalf("ask in default mode must deny and say why: %+v err=%v", wire, err)
	}
	wire, err = CodexPreToolUseOutput(ask, CodexBypassMode, CodexOptions{Ask: AskDeny})
	if err != nil || wire.Decision != PermissionDeny || !strings.Contains(string(wire.Output), "approvals are disabled") {
		t.Fatalf("ask in bypass mode must deny and say why: %+v err=%v", wire, err)
	}
	for _, mode := range []string{CodexDefaultMode, CodexBypassMode} {
		if wire, err := CodexPreToolUseOutput(ask, mode, CodexOptions{Ask: AskPassthrough}); err != nil || wire.Output != nil || wire.Decision != "" {
			t.Fatalf("ask with passthrough must print nothing in %s mode: %+v err=%v", mode, wire, err)
		}
	}
	for _, r := range []Result{{Permission: PermissionAllow, Reason: "ok"}, {}} {
		if wire, err := CodexPreToolUseOutput(r, CodexDefaultMode, CodexOptions{}); err != nil || wire.Output != nil {
			t.Fatalf("allow/passthrough must produce no PreToolUse output: %+v err=%v", wire, err)
		}
	}

	// PermissionRequest: a deny always answers; an allow only when opted in,
	// outside bypass mode, and for a plain request.
	plain := Input{HookEventName: CodexEventPermissionRequest, PermissionMode: CodexDefaultMode, ToolName: "Bash", ToolInput: json.RawMessage(`{"command":"git status"}`)}
	allow := Result{Permission: PermissionAllow, Reason: "Nomos: allows git status"}
	wire, err = CodexPermissionRequestOutput(deny, plain, CodexOptions{})
	if err != nil || wire.Decision != "deny" || !strings.Contains(string(wire.Output), `"behavior":"deny"`) || !strings.Contains(string(wire.Output), `"hookEventName":"PermissionRequest"`) {
		t.Fatalf("permission deny: %+v err=%v", wire, err)
	}
	if wire, err := CodexPermissionRequestOutput(allow, plain, CodexOptions{}); err != nil || wire.Output != nil {
		t.Fatalf("allow must stay silent unless opted in: %+v err=%v", wire, err)
	}
	wire, err = CodexPermissionRequestOutput(allow, plain, CodexOptions{PermissionRequestAllow: true})
	if err != nil || wire.Decision != "allow" || !strings.Contains(string(wire.Output), `"behavior":"allow"`) {
		t.Fatalf("opted-in allow: %+v err=%v", wire, err)
	}
	bypass := plain
	bypass.PermissionMode = CodexBypassMode
	if wire, err := CodexPermissionRequestOutput(allow, bypass, CodexOptions{PermissionRequestAllow: true}); err != nil || wire.Output != nil {
		t.Fatalf("allow must stay silent with approvals disabled (Codex's own reviewer may be asking): %+v err=%v", wire, err)
	}
	escalations := []json.RawMessage{
		json.RawMessage(`{"command":"git status","description":"network-access github.com"}`),
		json.RawMessage(`{"command":"git status","with_escalated_permissions":true}`),
		json.RawMessage(`{"command":"git status","justification":"needs the network"}`),
	}
	for _, input := range escalations {
		esc := plain
		esc.ToolInput = input
		if wire, err := CodexPermissionRequestOutput(allow, esc, CodexOptions{PermissionRequestAllow: true}); err != nil || wire.Output != nil {
			t.Fatalf("an escalation must never be allowed by Nomos: %s -> %+v err=%v", input, wire, err)
		}
		if wire, err := CodexPermissionRequestOutput(deny, esc, CodexOptions{PermissionRequestAllow: true}); err != nil || wire.Decision != "deny" {
			t.Fatalf("a deny still answers an escalation: %s -> %+v err=%v", input, wire, err)
		}
	}
	patchReq := plain
	patchReq.ToolName = CodexToolApplyPatch
	patchReq.ToolInput = json.RawMessage(`{"command":"*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch"}`)
	if wire, err := CodexPermissionRequestOutput(allow, patchReq, CodexOptions{PermissionRequestAllow: true}); err != nil || wire.Decision != "allow" {
		t.Fatalf("a plain apply_patch request may be allowed when opted in: %+v err=%v", wire, err)
	}
	for _, r := range []Result{ask, {}} {
		if wire, err := CodexPermissionRequestOutput(r, plain, CodexOptions{PermissionRequestAllow: true}); err != nil || wire.Output != nil {
			t.Fatalf("ask/passthrough must leave the approval flow alone: %+v err=%v", wire, err)
		}
	}
}

func TestCodexAuditEventsRecordTheWireDecision(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	in := toolInput(root, "Bash", map[string]any{"command": "git push origin main"})
	in.HookEventName = CodexEventPreToolUse
	in.PermissionMode = CodexBypassMode
	in.TurnID = "turn-7"
	in.ToolUseID = ""
	res, err := EvaluateMapping(engine, in, MapCodexToolCall(in, opts), opts)
	if err != nil || res.Permission != PermissionAsk {
		t.Fatalf("push must ask: %s %q err=%v", res.Permission, res.Reason, err)
	}
	copts := CodexOptions{Ask: AskDeny}
	wire, err := CodexPreToolUseOutput(res, in.PermissionMode, copts)
	if err != nil || wire.Decision != PermissionDeny {
		t.Fatalf("wire: %+v err=%v", wire, err)
	}
	events := CodexAuditEvents(in, res, wire, copts, opts, time.Unix(0, 0))
	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}
	md := events[0].ExecutorMetadata
	if md["hook_permission"] != PermissionAsk || md["wire_decision"] != PermissionDeny || md["ask_mode"] != AskDeny || md["turn_id"] != "turn-7" || md["outside_workspace"] != opts.OutsideWorkspace || md["permission_request_allow"] != false {
		t.Fatalf("metadata: %+v", md)
	}
	if !strings.HasPrefix(events[0].ActionID, "turn-7-") {
		t.Fatalf("action id must derive from the turn when tool_use_id is absent: %q", events[0].ActionID)
	}
	// Two different requests in one turn get distinct ids; the same
	// request gets the same id.
	other := in
	other.ToolInput = json.RawMessage(`{"command":"git status"}`)
	if other.callID() == in.callID() {
		t.Fatalf("distinct requests must not share an action id")
	}
	same := in
	if same.callID() != in.callID() {
		t.Fatalf("the id must be deterministic")
	}
	silent := CodexAuditEvents(in, res, CodexWire{}, CodexOptions{Ask: AskPassthrough}, opts, time.Unix(0, 0))
	if silent[0].ExecutorMetadata["wire_decision"] != "none" || silent[0].ExecutorMetadata["ask_mode"] != AskPassthrough {
		t.Fatalf("silent metadata: %+v", silent[0].ExecutorMetadata)
	}
}

func TestCodexMatcherStaysAnchored(t *testing.T) {
	cases := map[[2]string]string{
		{CodexDefaultMatcher, "false"}: CodexDefaultMatcher,
		{CodexDefaultMatcher, "true"}:  "^(Bash|apply_patch|Write|Edit|mcp__.*)$",
		{"Bash", "true"}:               "^(Bash|mcp__.*)$",
		{"^Bash$", "true"}:             "^Bash$|^mcp__.*$",
		{"Bash|mcp__.*", "true"}:       "Bash|mcp__.*",
		{"", "false"}:                  CodexDefaultMatcher,
	}
	for key, want := range cases {
		if got := CodexMatcher(key[0], key[1] == "true"); got != want {
			t.Fatalf("CodexMatcher(%q, %s) = %q, want %q", key[0], key[1], got, want)
		}
	}
}

func TestInstallCodexHooksMergesAndStaysIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".codex", "hooks.json")
	existing := `{"description":"team hooks","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"lint-check","timeout":5}]}],"PostToolUse":[]}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	changed, err := InstallCodexHooks(path, "nomos hook codex --profile safe-dev", "", 0, true)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	data, _ := os.ReadFile(path)
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc["description"] != "team hooks" {
		t.Fatalf("other keys must survive: %v", doc)
	}
	hooks := doc["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("existing PreToolUse entry must be kept: %v", pre)
	}
	perm := hooks["PermissionRequest"].([]any)
	if len(perm) != 1 {
		t.Fatalf("PermissionRequest entry: %v", perm)
	}
	entry := perm[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	for key := range entry {
		if key != "type" && key != "command" && key != "timeout" {
			t.Fatalf("unexpected key %q: Codex rejects unknown fields", key)
		}
	}
	if entry["timeout"] != float64(DefaultTimeoutSeconds) || entry["command"] != "nomos hook codex --profile safe-dev" {
		t.Fatalf("entry: %v", entry)
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Fatalf("unrelated events must be preserved")
	}
	changed, err = InstallCodexHooks(path, "nomos hook codex --profile safe-dev", "", 0, true)
	if err != nil || changed {
		t.Fatalf("second install must be a no-op: changed=%v err=%v", changed, err)
	}
	if _, err := InstallCodexHooks(path, "something-else", "", 0, true); err == nil {
		t.Fatalf("a command that does not invoke the hook must be rejected")
	}
	if _, err := InstallCodexHooks(path, "nomos hook codex", "", 0, false); err != nil {
		t.Fatalf("install without permission request: %v", err)
	}
	// A file Codex would refuse (unknown top-level key or event) is not
	// silently extended, because Codex drops the whole file and the hook
	// would never run.
	for name, content := range map[string]string{
		"extra-key":     `{"hooks":{},"extra":true}`,
		"unknown-event": `{"hooks":{"OnToolCall":[]}}`,
	} {
		bad := filepath.Join(dir, name+".json")
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := InstallCodexHooks(bad, "nomos hook codex", "", 0, true); err == nil || !strings.Contains(err.Error(), "Codex rejects") {
			t.Fatalf("%s: install must refuse a file Codex rejects, got %v", name, err)
		}
		after, _ := os.ReadFile(bad)
		if string(after) != content {
			t.Fatalf("%s: a refused file must be left untouched: %s", name, after)
		}
	}
}
