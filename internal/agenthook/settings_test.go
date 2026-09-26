package agenthook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallHookCreatesMergesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	cmd := "nomos hook claude-code --profile safe-dev"

	changed, err := InstallHook(path, cmd, "", 0)
	if err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("decode: %v", err)
	}
	entries := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected one PreToolUse entry, got %d", len(entries))
	}
	entry := entries[0].(map[string]any)
	if entry["matcher"] != DefaultMatcher {
		t.Fatalf("matcher: %v", entry["matcher"])
	}
	inner := entry["hooks"].([]any)[0].(map[string]any)
	if inner["command"] != cmd || inner["type"] != "command" || inner["timeout"] != float64(DefaultTimeoutSeconds) {
		t.Fatalf("inner hook: %v", inner)
	}

	changed, err = InstallHook(path, cmd, "", 0)
	if err != nil || changed {
		t.Fatalf("second install must be a no-op: changed=%v err=%v", changed, err)
	}
}

func TestInstallHookPreservesExistingSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	existing := `{
  "permissions": {"deny": ["Bash(rm -rf *)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Write", "hooks": [{"type": "command", "command": "prettier --check"}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]
  },
  "model": "opus"
}`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	changed, err := InstallHook(path, "nomos hook claude-code -p policy.yaml", "Bash", 5)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{`"permissions"`, `Bash(rm -rf *)`, `prettier --check`, `"Stop"`, `"model": "opus"`, `nomos hook claude-code -p policy.yaml`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q preserved in settings:\n%s", want, text)
		}
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("decode: %v", err)
	}
	entries := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected existing entry plus nomos entry, got %d", len(entries))
	}
}

func TestInstallHookRejectsForeignCommandsAndBadShapes(t *testing.T) {
	dir := t.TempDir()
	if _, err := InstallHook(filepath.Join(dir, "s.json"), "rm -rf /", "", 0); err == nil {
		t.Fatal("expected rejection of a command that is not the nomos hook")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"hooks": []}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := InstallHook(bad, "nomos hook claude-code", "", 0); err == nil {
		t.Fatal("expected error when hooks is not an object")
	}
}
