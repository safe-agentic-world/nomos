package agenthook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	out, err := CodexPreToolUseOutput(deny, "default", AskInBypassDeny)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	var wire struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &wire); err != nil || wire.HookSpecificOutput.HookEventName != "PreToolUse" || wire.HookSpecificOutput.PermissionDecision != "deny" || wire.HookSpecificOutput.PermissionDecisionReason != "Nomos: profile denies rm" {
		t.Fatalf("deny wire: %s err=%v", out, err)
	}
	var generic map[string]any
	_ = json.Unmarshal(out, &generic)
	if len(generic) != 1 {
		t.Fatalf("PreToolUse output must carry only hookSpecificOutput (Codex rejects unknown fields): %s", out)
	}

	ask := Result{Permission: PermissionAsk, Reason: "Nomos: requires confirmation"}
	if out, err := CodexPreToolUseOutput(ask, "default", AskInBypassDeny); err != nil || out != nil {
		t.Fatalf("ask in default mode must produce no PreToolUse output: %s err=%v", out, err)
	}
	out, err = CodexPreToolUseOutput(ask, CodexBypassMode, AskInBypassDeny)
	if err != nil || !strings.Contains(string(out), `"permissionDecision":"deny"`) || !strings.Contains(string(out), "bypassPermissions") {
		t.Fatalf("ask in bypass mode must deny: %s err=%v", out, err)
	}
	if out, err := CodexPreToolUseOutput(ask, CodexBypassMode, AskInBypassPassthrough); err != nil || out != nil {
		t.Fatalf("ask in bypass with passthrough must produce no output: %s err=%v", out, err)
	}
	for _, r := range []Result{{Permission: PermissionAllow, Reason: "ok"}, {}} {
		if out, err := CodexPreToolUseOutput(r, "default", AskInBypassDeny); err != nil || out != nil {
			t.Fatalf("allow/passthrough must produce no PreToolUse output: %s err=%v", out, err)
		}
	}

	out, err = CodexPermissionRequestOutput(Result{Permission: PermissionAllow, Reason: "Nomos: allows git status"})
	if err != nil || !strings.Contains(string(out), `"behavior":"allow"`) || !strings.Contains(string(out), `"hookEventName":"PermissionRequest"`) {
		t.Fatalf("permission allow: %s err=%v", out, err)
	}
	out, err = CodexPermissionRequestOutput(deny)
	if err != nil || !strings.Contains(string(out), `"behavior":"deny"`) {
		t.Fatalf("permission deny: %s err=%v", out, err)
	}
	for _, r := range []Result{ask, {}} {
		if out, err := CodexPermissionRequestOutput(r); err != nil || out != nil {
			t.Fatalf("ask/passthrough must leave the approval flow alone: %s err=%v", out, err)
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
}
