package agenthook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

const testBundleYAML = `version: v1
rules:
  - id: allow-git-readonly
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["git", "status"]
        - ["git", "diff", "**"]
  - id: approve-git-push
    action_type: process.exec
    resource: file://workspace/
    decision: REQUIRE_APPROVAL
    exec_match:
      argv_patterns:
        - ["git", "push", "**"]
  - id: allow-cat
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["cat", "**"]
  - id: deny-secret-file-args
    action_type: process.exec
    resource: file://workspace/
    decision: DENY
    exec_match:
      argv_patterns:
        - ["**", "*.env", "**"]
        - ["**", "*.pem", "**"]
  - id: deny-home-wipe
    action_type: process.exec
    resource: file://workspace/
    decision: DENY
    exec_match:
      argv_patterns:
        - ["rm", "**", "~*", "**"]
  - id: deny-dotenv-read
    action_type: fs.read
    resource: file://workspace/**/.env
    decision: DENY
  - id: allow-workspace-read
    action_type: fs.read
    resource: file://workspace/**
    decision: ALLOW
  - id: allow-workspace-write
    action_type: fs.write
    resource: file://workspace/**
    decision: ALLOW
  - id: allow-github-get
    action_type: net.http_request
    resource: url://github.com/**
    decision: ALLOW
`

func testEngine(t *testing.T) *policy.Engine {
	t.Helper()
	bundle, err := policy.LoadBundleBytes([]byte(testBundleYAML), "test.yaml")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return policy.NewEngine(bundle)
}

func testOptions(t *testing.T, root string) Options {
	t.Helper()
	return Options{
		WorkspaceRoot:    root,
		Identity:         identity.VerifiedIdentity{Principal: "developer", Agent: "claude-code", Environment: "local"},
		OnDefaultDeny:    ModeAsk,
		OnUnsupported:    ModeAsk,
		OutsideWorkspace: ModeAsk,
		BundleLabel:      "test.yaml",
		HomeDir:          filepath.Join(root, "..", "home"),
	}
}

func bashInput(root, command string) Input {
	raw, _ := json.Marshal(map[string]any{"command": command})
	return Input{SessionID: "sess-1", Cwd: root, HookEventName: "PreToolUse", PermissionMode: "default", ToolName: "Bash", ToolInput: raw, ToolUseID: "toolu_01"}
}

func toolInput(root, tool string, fields map[string]any) Input {
	raw, _ := json.Marshal(fields)
	return Input{SessionID: "sess-1", Cwd: root, HookEventName: "PreToolUse", ToolName: tool, ToolInput: raw, ToolUseID: "toolu_02"}
}

func newWorkspace(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(base, "home", ".ssh"), 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	return resolved
}

func TestEvaluateBashDecisions(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	cases := []struct {
		name       string
		command    string
		opts       func(Options) Options
		want       string
		reasonPart string
	}{
		{name: "allowed readonly git", command: "git status", want: PermissionAllow, reasonPart: "allow-git-readonly"},
		{name: "approval maps to ask", command: "git push origin main", want: PermissionAsk, reasonPart: "approve-git-push"},
		{name: "chain: deny wins over approval and allow", command: "git status && git push origin main && cat config/.env", want: PermissionDeny, reasonPart: "deny-secret-file-args"},
		{name: "chain: ask wins over allow", command: "git status && git push origin main", want: PermissionAsk, reasonPart: "approve-git-push"},
		{name: "by-path rm of home is denied by rule", command: "/bin/rm -rf ~/", want: PermissionDeny, reasonPart: "deny-home-wipe"},
		{name: "incident command is denied", command: "rm -rf tests/ patches/ plan/ ~/", want: PermissionDeny, reasonPart: "deny-home-wipe"},
		{name: "sh -c wrapper is unwrapped and secret arg denied", command: `sh -c "git status && cat .env"`, want: PermissionDeny, reasonPart: "deny-secret-file-args"},
		{name: "unknown command asks by default", command: "make build", want: PermissionAsk, reasonPart: "no test.yaml rule allows"},
		{name: "unknown command denies in strict mode", command: "make build", opts: func(o Options) Options { o.OnDefaultDeny = ModeDeny; return o }, want: PermissionDeny, reasonPart: "deny by default"},
		{name: "variable expansion asks", command: "rm -rf $HOME", want: PermissionAsk, reasonPart: "cannot safely interpret"},
		{name: "variable expansion denies in strict mode", command: "rm -rf $HOME", opts: func(o Options) Options { o.OnUnsupported = ModeDeny; return o }, want: PermissionDeny, reasonPart: "cannot safely interpret"},
		{name: "allowed command with outside path asks", command: "cat /etc/hostname", want: PermissionAsk, reasonPart: "outside the workspace"},
		{name: "allowed command with outside path denies in strict mode", command: "cat /etc/hostname", opts: func(o Options) Options { o.OutsideWorkspace = ModeDeny; return o }, want: PermissionDeny, reasonPart: "outside the workspace"},
		{name: "allowed command with outside path passes through boundary check", command: "cat /etc/hostname", opts: func(o Options) Options { o.OutsideWorkspace = ModePassthrough; return o }, want: PermissionAllow, reasonPart: "allow-cat"},
		{name: "cd outside then allowed command asks", command: "cd /tmp && git status", want: PermissionAsk, reasonPart: "working directory"},
		{name: "parent escape asks", command: "cat ../secret.txt", want: PermissionAsk, reasonPart: "outside the workspace"},
		{name: "relative path inside stays allowed", command: "cat ./src/main.go", want: PermissionAllow, reasonPart: "allow-cat"},
		{name: "git refs are not paths", command: "git diff origin/main", want: PermissionAllow, reasonPart: "allow-git-readonly"},
		{name: "sudo asks", command: "sudo git status", want: PermissionAsk, reasonPart: "privilege escalation"},
		{name: "empty command asks", command: "   ", want: PermissionAsk, reasonPart: "empty command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			if tc.opts != nil {
				o = tc.opts(o)
			}
			res, err := Evaluate(engine, bashInput(root, tc.command), o)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Permission != tc.want {
				t.Fatalf("command %q: got %s (%s) want %s", tc.command, res.Permission, res.Reason, tc.want)
			}
			if !strings.Contains(res.Reason, tc.reasonPart) {
				t.Fatalf("command %q: reason %q lacks %q", tc.command, res.Reason, tc.reasonPart)
			}
			if !strings.HasPrefix(res.Reason, "Nomos: ") {
				t.Fatalf("reason must be attributed: %q", res.Reason)
			}
		})
	}
}

func TestEvaluateFileToolsAndWorkspaceBoundary(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)

	res, err := Evaluate(engine, toolInput(root, "Read", map[string]any{"file_path": filepath.Join(root, "src", "main.go")}), opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("read inside: %s %q err=%v", res.Permission, res.Reason, err)
	}
	if got := res.Outcomes[0].Action.Resource; got != "file://workspace/src/main.go" {
		t.Fatalf("resource: %q", got)
	}

	res, err = Evaluate(engine, toolInput(root, "Read", map[string]any{"file_path": ".env"}), opts)
	if err != nil || res.Permission != PermissionDeny || !strings.Contains(res.Reason, "deny-dotenv-read") {
		t.Fatalf("read dotenv: %s %q err=%v", res.Permission, res.Reason, err)
	}

	res, err = Evaluate(engine, toolInput(root, "Write", map[string]any{"file_path": "src/new file.go", "content": "x"}), opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("write inside: %s %q err=%v", res.Permission, res.Reason, err)
	}
	if got := res.Outcomes[0].Action.Resource; got != "file://workspace/src/new%20file.go" {
		t.Fatalf("escaped resource: %q", got)
	}

	res, err = Evaluate(engine, toolInput(root, "Edit", map[string]any{"file_path": "/etc/passwd", "old_string": "a", "new_string": "b"}), opts)
	if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
		t.Fatalf("edit outside: %s %q err=%v", res.Permission, res.Reason, err)
	}
	strict := opts
	strict.OutsideWorkspace = ModeDeny
	res, _ = Evaluate(engine, toolInput(root, "Edit", map[string]any{"file_path": "/etc/passwd"}), strict)
	if res.Permission != PermissionDeny {
		t.Fatalf("edit outside strict: %s", res.Permission)
	}
	pass := opts
	pass.OutsideWorkspace = ModePassthrough
	res, _ = Evaluate(engine, toolInput(root, "Edit", map[string]any{"file_path": "/etc/passwd"}), pass)
	if !res.Passthrough() {
		t.Fatalf("edit outside passthrough must yield no decision, got %s", res.Permission)
	}

	res, _ = Evaluate(engine, toolInput(root, "Read", map[string]any{"file_path": "../other/file"}), opts)
	if res.Permission != PermissionAsk {
		t.Fatalf("parent escape: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, toolInput(root, "Read", map[string]any{"file_path": "~/.ssh/id_rsa"}), opts)
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
		t.Fatalf("home read: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, toolInput(root, "NotebookEdit", map[string]any{"notebook_path": "nb.ipynb"}), opts)
	if res.Permission != PermissionAllow {
		t.Fatalf("notebook edit inside: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, toolInput(root, "Read", map[string]any{}), opts)
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "without a path") {
		t.Fatalf("read without path: %s %q", res.Permission, res.Reason)
	}
}

func TestEvaluateDetectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	root := newWorkspace(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	engine := testEngine(t)
	opts := testOptions(t, root)
	res, err := Evaluate(engine, toolInput(root, "Write", map[string]any{"file_path": "link/escape.txt"}), opts)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
		t.Fatalf("symlinked write must be treated as outside: %s %q", res.Permission, res.Reason)
	}
}

func TestEvaluateURLAndMCPAndPassthrough(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)

	res, err := Evaluate(engine, toolInput(root, "WebFetch", map[string]any{"url": "https://github.com/safe-agentic-world/nomos", "prompt": "summarize"}), opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("github fetch: %s %q err=%v", res.Permission, res.Reason, err)
	}
	if got := res.Outcomes[0].Action.Resource; got != "url://github.com/safe-agentic-world/nomos" {
		t.Fatalf("url resource: %q", got)
	}
	res, _ = Evaluate(engine, toolInput(root, "WebFetch", map[string]any{"url": "https://evil.example.com/x"}), opts)
	if res.Permission != PermissionAsk {
		t.Fatalf("unknown host must ask: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, toolInput(root, "WebFetch", map[string]any{"url": "https://user:pw@github.com/x"}), opts)
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "credentials") {
		t.Fatalf("url with credentials: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, toolInput(root, "mcp__github__search_repositories", map[string]any{"query": "nomos"}), opts)
	if res.Permission != PermissionAsk {
		t.Fatalf("mcp default deny must ask: %s %q", res.Permission, res.Reason)
	}
	if got := res.Outcomes[0].Action.Resource; got != "mcp://github/search_repositories" {
		t.Fatalf("mcp resource: %q", got)
	}
	res, _ = Evaluate(engine, toolInput(root, "Grep", map[string]any{"pattern": "x"}), opts)
	if !res.Passthrough() {
		t.Fatalf("unmapped tool must pass through, got %s", res.Permission)
	}
	out, err := res.HookOutput()
	if err != nil || out != nil {
		t.Fatalf("passthrough output must be nil: %q err=%v", out, err)
	}
	res, _ = Evaluate(engine, bashInput(root, "cd src"), opts)
	if !res.Passthrough() {
		t.Fatalf("cd inside workspace alone must pass through, got %s %q", res.Permission, res.Reason)
	}
}

func TestHookOutputShapeAndAuditEvents(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	res, err := Evaluate(engine, bashInput(root, "git status && cat config/.env"), opts)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	out, err := res.HookOutput()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	var decoded struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.HookSpecificOutput.HookEventName != "PreToolUse" || decoded.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("unexpected output: %s", out)
	}
	if !strings.Contains(decoded.HookSpecificOutput.PermissionDecisionReason, "deny-secret-file-args") {
		t.Fatalf("reason: %q", decoded.HookSpecificOutput.PermissionDecisionReason)
	}

	events := AuditEvents(bashInput(root, "git status && cat config/.env"), res, opts, time.Date(2026, 9, 25, 20, 0, 0, 0, time.UTC))
	if len(events) != 2 {
		t.Fatalf("expected one event per command, got %d", len(events))
	}
	first, second := events[0], events[1]
	if first.EventType != "hook.decision" || first.ActionType != "process.exec" || first.Decision != "ALLOW" || first.MatchedRuleIDs[0] != "allow-git-readonly" {
		t.Fatalf("first event: %+v", first)
	}
	if second.Decision != "DENY" || second.Reason != "deny_by_rule" || second.ParamsHash == "" || second.PolicyBundleHash == "" {
		t.Fatalf("second event: %+v", second)
	}
	if second.ExecutorMetadata["hook_permission"] != "deny" || second.ExecutorMetadata["tool_name"] != "Bash" {
		t.Fatalf("metadata: %+v", second.ExecutorMetadata)
	}
	if first.TraceID != "sess-1" || first.ActionID != "toolu_01-0" || second.ActionID != "toolu_01-1" {
		t.Fatalf("ids: %q %q %q", first.TraceID, first.ActionID, second.ActionID)
	}
	if !strings.Contains(second.ActionSummary, `"config/.env"`) {
		t.Fatalf("summary must carry argv: %q", second.ActionSummary)
	}
}

func TestParseInputValidation(t *testing.T) {
	if _, err := ParseInput(strings.NewReader(`{"tool_input":{"command":"ls"}}`)); err == nil {
		t.Fatal("expected error without tool_name")
	}
	if _, err := ParseInput(strings.NewReader(`not json`)); err == nil {
		t.Fatal("expected decode error")
	}
	in, err := ParseInput(strings.NewReader(`{"tool_name":"Bash","future_field":1}`))
	if err != nil {
		t.Fatalf("unknown fields must be tolerated: %v", err)
	}
	if string(in.ToolInput) != "{}" {
		t.Fatalf("missing tool_input must default to {}: %s", in.ToolInput)
	}
	big := `{"tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("a", maxInputBytes) + `"}}`
	if _, err := ParseInput(strings.NewReader(big)); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestEvaluateRejectsInvalidOptions(t *testing.T) {
	engine := testEngine(t)
	root := newWorkspace(t)
	bad := testOptions(t, root)
	bad.WorkspaceRoot = "relative/path"
	if _, err := Evaluate(engine, bashInput(root, "ls"), bad); err == nil {
		t.Fatal("expected error for relative workspace root")
	}
	bad = testOptions(t, root)
	bad.OnDefaultDeny = "allow"
	if _, err := Evaluate(engine, bashInput(root, "ls"), bad); err == nil {
		t.Fatal("expected error for invalid on-default mode")
	}
	bad = testOptions(t, root)
	bad.Identity = identity.VerifiedIdentity{}
	if _, err := Evaluate(engine, bashInput(root, "ls"), bad); err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestReasonsAreRedacted(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	res, err := Evaluate(engine, bashInput(root, `curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz" https://api.example.com`), opts)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if strings.Contains(res.Reason, "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("reason leaked a bearer token: %q", res.Reason)
	}
}
