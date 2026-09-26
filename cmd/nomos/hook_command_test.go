package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/audit"
)

const hookTestBundle = `version: v1
rules:
  - id: allow-git-status
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["git", "status"]
  - id: approve-git-push
    action_type: process.exec
    resource: file://workspace/
    decision: REQUIRE_APPROVAL
    exec_match:
      argv_patterns:
        - ["git", "push", "**"]
  - id: deny-home-wipe
    action_type: process.exec
    resource: file://workspace/
    decision: DENY
    exec_match:
      argv_patterns:
        - ["rm", "**", "~*", "**"]
`

func noEnv(string) string { return "" }

func writeHookBundle(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(hookTestBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func decodeHookDecision(t *testing.T, out string) (string, string) {
	t.Helper()
	var payload struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &payload); err != nil {
		t.Fatalf("decode hook output %q: %v", out, err)
	}
	return payload.HookSpecificOutput.PermissionDecision, payload.HookSpecificOutput.PermissionDecisionReason
}

func TestClaudeCodeHookSimulateDecisions(t *testing.T) {
	dir := t.TempDir()
	bundle := writeHookBundle(t, dir)
	cases := []struct {
		command string
		want    string
	}{
		{"git status", "allow"},
		{"git push origin main", "ask"},
		{"rm -rf ~/", "deny"},
		{"/bin/rm -rf tests/ ~/", "deny"},
		{"make", "ask"},
	}
	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		code := runClaudeCodeHook([]string{"-p", bundle, "--workspace", dir, "--audit", "none", "--simulate", "--command", tc.command}, strings.NewReader(""), &stdout, &stderr, noEnv)
		if code != 0 {
			t.Fatalf("%q: exit %d stderr=%s", tc.command, code, stderr.String())
		}
		got, _ := decodeHookDecision(t, stdout.String())
		if got != tc.want {
			t.Fatalf("%q: got %s want %s (stderr: %s)", tc.command, got, tc.want, stderr.String())
		}
		if !strings.Contains(stderr.String(), "decision: "+tc.want) {
			t.Fatalf("%q: simulate must explain on stderr, got %q", tc.command, stderr.String())
		}
	}
}

func TestClaudeCodeHookStdinDeniesAndWritesVerifiableAudit(t *testing.T) {
	dir := t.TempDir()
	bundle := writeHookBundle(t, dir)
	input := `{"session_id":"sess-42","cwd":"` + filepath.ToSlash(dir) + `","hook_event_name":"PreToolUse","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"rm -rf tests/ patches/ plan/ ~/"},"tool_use_id":"toolu_9"}`
	var stdout, stderr bytes.Buffer
	code := runClaudeCodeHook([]string{"-p", bundle}, strings.NewReader(input), &stdout, &stderr, noEnv)
	if code != 0 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
	decision, reason := decodeHookDecision(t, stdout.String())
	if decision != "deny" || !strings.Contains(reason, "deny-home-wipe") {
		t.Fatalf("decision=%s reason=%q", decision, reason)
	}
	auditPath := filepath.Join(dir, ".nomos", defaultHookAuditFile)
	// One record for the evaluated process.exec plus one for the
	// outside-workspace finding on "~/".
	count, err := audit.VerifyFileChain(auditPath)
	if err != nil || count != 2 {
		t.Fatalf("audit chain: count=%d err=%v", count, err)
	}
	data, _ := os.ReadFile(auditPath)
	text := string(data)
	for _, want := range []string{`"permission_mode":"bypassPermissions"`, `"hook_permission":"deny"`, `"matched_rule_ids":["deny-home-wipe"]`, `"decision":"OUTSIDE_WORKSPACE"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit records lack %s:\n%s", want, text)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = runClaudeCodeHook([]string{"--verify-audit", "--workspace", dir}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 || !strings.Contains(stdout.String(), "verified 2 chained audit events") {
		t.Fatalf("verify: exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClaudeCodeHookUsesProjectDirEnvAndPassesThroughUnknownTools(t *testing.T) {
	dir := t.TempDir()
	bundle := writeHookBundle(t, dir)
	env := func(key string) string {
		if key == "CLAUDE_PROJECT_DIR" {
			return dir
		}
		return ""
	}
	input := `{"tool_name":"Grep","tool_input":{"pattern":"x"},"cwd":"` + filepath.ToSlash(dir) + `"}`
	var stdout, stderr bytes.Buffer
	code := runClaudeCodeHook([]string{"-p", bundle}, strings.NewReader(input), &stdout, &stderr, env)
	if code != 0 || strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("passthrough: exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".nomos", defaultHookAuditFile)); !os.IsNotExist(err) {
		t.Fatalf("passthrough must not write audit, stat err=%v", err)
	}
}

func TestClaudeCodeHookFailsClosedOnErrors(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runClaudeCodeHook([]string{"-p", filepath.Join(dir, "missing.yaml"), "--simulate", "--command", "ls"}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("missing bundle must exit %d, got %d", hookExitError, code)
	}
	bundle := writeHookBundle(t, dir)
	stdout.Reset()
	stderr.Reset()
	if code := runClaudeCodeHook([]string{"-p", bundle}, strings.NewReader(`{"tool_input":{}}`), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("input without tool_name must exit %d, got %d", hookExitError, code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runClaudeCodeHook([]string{"-p", bundle, "--profile", "safe-dev", "--simulate", "--command", "ls"}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("conflicting policy flags must exit %d, got %d", hookExitError, code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runClaudeCodeHook([]string{"-p", bundle, "--on-default", "allow", "--simulate", "--command", "ls"}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("invalid mode must exit %d, got %d", hookExitError, code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runClaudeCodeHook([]string{"-p", bundle, "--simulate"}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("simulate without tool must exit %d, got %d", hookExitError, code)
	}
}

func TestClaudeCodeHookPrintSettingsAndInstall(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runClaudeCodeHook([]string{"--print-settings", "--profile", "ci-strict", "--on-default", "deny", "--mcp"}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 {
		t.Fatalf("print-settings exit %d: %s", code, stderr.String())
	}
	var snippet map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &snippet); err != nil {
		t.Fatalf("decode snippet: %v", err)
	}
	entry := snippet["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if !strings.Contains(entry["matcher"].(string), "mcp__.*") {
		t.Fatalf("matcher must include mcp when requested: %v", entry["matcher"])
	}
	inner := entry["hooks"].([]any)[0].(map[string]any)
	if inner["command"] != "nomos hook claude-code --profile ci-strict --on-default deny" {
		t.Fatalf("command: %v", inner["command"])
	}

	stdout.Reset()
	stderr.Reset()
	code = runClaudeCodeHook([]string{"--install", "--workspace", dir, "--profile", "safe-dev"}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 || !strings.Contains(stdout.String(), "installed Nomos PreToolUse hook") {
		t.Fatalf("install: exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("settings not written: %v", err)
	}
	if !strings.Contains(string(data), "nomos hook claude-code --profile safe-dev") {
		t.Fatalf("settings content: %s", data)
	}
	stdout.Reset()
	code = runClaudeCodeHook([]string{"--install", "--workspace", dir, "--profile", "safe-dev"}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 || !strings.Contains(stdout.String(), "already registered") {
		t.Fatalf("second install: exit %d stdout=%q", code, stdout.String())
	}
}

func TestClaudeCodeHookEmbeddedProfileSafeDev(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runClaudeCodeHook([]string{"--workspace", dir, "--audit", "none", "--simulate", "--command", "git status"}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if got, _ := decodeHookDecision(t, stdout.String()); got != "allow" {
		t.Fatalf("safe-dev git status: %s (%s)", got, stderr.String())
	}
}

func TestClaudeCodeHookReplayReportsDecisions(t *testing.T) {
	dir := t.TempDir()
	bundle := writeHookBundle(t, dir)
	replay := filepath.Join(dir, "calls.jsonl")
	lines := "git status\n" +
		`{"command":"git push origin main"}` + "\n" +
		`{"tool_name":"Read","tool_input":{"file_path":"src/main.go"}}` + "\n" +
		`{"type":"assistant","cwd":"` + dir + `","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf ~/"}}]}}` + "\n" +
		`{"tool_name":"TodoWrite","tool_input":{}}` + "\n"
	if err := os.WriteFile(replay, []byte(lines), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runClaudeCodeHook([]string{"-p", bundle, "--workspace", dir, "--replay", replay, "--format", "json"}, strings.NewReader(""), &stdout, &stderr, noEnv)
	if code != 0 {
		t.Fatalf("replay exit %d stderr=%s", code, stderr.String())
	}
	var report struct {
		Records     int            `json:"records"`
		Skipped     int            `json:"skipped_tools"`
		Permissions map[string]int `json:"permissions"`
		Denies      []struct {
			Command string `json:"command"`
		} `json:"denies"`
		Asks []struct {
			Class string `json:"class"`
		} `json:"asks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if report.Records != 4 || report.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d", report.Records, report.Skipped)
	}
	if report.Permissions["allow"] != 1 || report.Permissions["ask"] != 2 || report.Permissions["deny"] != 1 {
		t.Fatalf("permissions: %+v", report.Permissions)
	}
	if len(report.Denies) != 1 || report.Denies[0].Command != "rm -rf ~/" {
		t.Fatalf("denies: %+v", report.Denies)
	}
	if len(report.Asks) != 2 {
		t.Fatalf("json report must list asks: %+v", report.Asks)
	}
	stdout.Reset()
	stderr.Reset()
	code = runClaudeCodeHook([]string{"-p", bundle, "--workspace", dir, "--replay", "-", "--show-asks"}, strings.NewReader("git status\ngit push origin main\n"), &stdout, &stderr, noEnv)
	if code != 0 {
		t.Fatalf("stdin replay exit %d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"replay of 2 tool calls", "calls that would ask:", "git push origin main"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("text report missing %q:\n%s", want, stdout.String())
		}
	}
	if code := runClaudeCodeHook([]string{"-p", bundle, "--replay", replay, "--format", "xml"}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("bad format must fail closed, got %d", code)
	}
	if code := runClaudeCodeHook([]string{"-p", bundle, "--replay-transcripts", "--transcripts-dir", filepath.Join(dir, "missing")}, strings.NewReader(""), &stdout, &stderr, noEnv); code != hookExitError {
		t.Fatalf("missing transcript dir must fail, got %d", code)
	}
}
