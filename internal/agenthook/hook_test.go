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
	"github.com/safe-agentic-world/nomos/internal/launcher"
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

func TestEvaluateDetectsSymlinkFollowedByDotDotEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	root := newWorkspace(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.MkdirAll(filepath.Join(outside, "deep"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The kernel resolves `link` before applying `..`, so `link/../secret.txt`
	// opens the file outside the workspace even though the cleaned text
	// `secret.txt` names a file inside it.
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	engine := testEngine(t)
	opts := testOptions(t, root)

	for _, command := range []string{
		"cat link/../secret.txt",
		"cat ./link/./../secret.txt",
		"cat sub/../link/../secret.txt",
		"cat link/nested/../../secret.txt",
	} {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": command}), opts)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", command, err)
		}
		if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
			t.Fatalf("%s: symlink then .. must be treated as outside: %s %q", command, res.Permission, res.Reason)
		}
	}
	for _, tool := range []struct {
		name  string
		input map[string]any
	}{
		{"Read", map[string]any{"file_path": "link/../secret.txt"}},
		{"Write", map[string]any{"file_path": "link/../new.txt", "content": "x"}},
	} {
		res, err := Evaluate(engine, toolInput(root, tool.name, tool.input), opts)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", tool.name, err)
		}
		if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
			t.Fatalf("%s: symlink then .. must be treated as outside: %s %q", tool.name, res.Permission, res.Reason)
		}
	}

	// A real (or not yet existing) directory followed by `..` stays inside.
	for _, command := range []string{"cat sub/../secret.txt", "cat newdir/../secret.txt"} {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": command}), opts)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", command, err)
		}
		if res.Permission != PermissionAllow {
			t.Fatalf("%s: inside path must stay allowed: %s %q", command, res.Permission, res.Reason)
		}
	}
	res, err := Evaluate(engine, toolInput(root, "Write", map[string]any{"file_path": "sub/../new.txt", "content": "x"}), opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("inside write must stay allowed: %s %q err=%v", res.Permission, res.Reason, err)
	}
}

func TestPhysicalPathResolvesSymlinksBeforeDotDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	base := t.TempDir()
	target := filepath.Join(base, "target", "deep")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(filepath.Join(ws, "real"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(ws, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	cases := map[string]string{
		"link/../x":          filepath.Join(resolvedBase, "target", "x"),
		"link/../../x":       filepath.Join(resolvedBase, "x"),
		"real/../x":          filepath.Join(resolvedBase, "ws", "x"),
		"missing/../x":       filepath.Join(resolvedBase, "ws", "x"),
		"./link/./deeper/..": filepath.Join(resolvedBase, "target", "deep"),
		"x":                  filepath.Join(resolvedBase, "ws", "x"),
		ws + "/link/../x":    filepath.Join(resolvedBase, "target", "x"),
	}
	for in, want := range cases {
		if got := physicalPath(ws, in); got != want {
			t.Fatalf("physicalPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := physicalPath("/", "/../etc/../x"); got != string(filepath.Separator)+"x" {
		t.Fatalf("root parent must stay at root: %q", got)
	}
}

func TestPathCandidatesInspectOptionValuesAndEmbeddedPaths(t *testing.T) {
	cases := []struct {
		tok  string
		want []string
	}{
		{"../user@corp-secret.txt", []string{"../user@corp-secret.txt"}},
		{"./at@dir/../../secret.txt", []string{"./at@dir/../../secret.txt"}},
		{"git@github.com:org/repo.git", []string{"git@github.com:org/repo.git"}},
		{"https://example.com/x", []string{"https://example.com/x"}},
		{"-C/tmp", []string{"/tmp"}},
		{"-C..", []string{".."}},
		{"-C~", []string{"~"}},
		{"-o../out.txt", []string{"../out.txt"}},
		{"-Wl,-rpath,/usr/lib", []string{"l,-rpath,/usr/lib", "/usr/lib"}},
		{"--prefix=/opt", []string{"/opt"}},
		{"--mount=type=bind,src=/etc,dst=/x", []string{"type=bind,src=/etc,dst=/x", "/etc", "/x"}},
		{"DESTDIR=/tmp/x", []string{"DESTDIR=/tmp/x", "/tmp/x"}},
		{"sub/a,b", []string{"sub/a,b", "sub/a"}},
		{`..\secret.txt`, []string{`..\secret.txt`}},
		{`C:\Users\x`, []string{`C:\Users\x`}},
		{"-rf", nil},
		{"-", nil},
		{"--", nil},
		{"--verbose", nil},
		{"plain", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := pathCandidates(tc.tok)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("pathCandidates(%q) = %q, want %q", tc.tok, got, tc.want)
		}
	}
}

func TestEvaluateChecksPathsWithAtSignsAndGluedOptionValues(t *testing.T) {
	root := newWorkspace(t)
	outside := filepath.Dir(root)
	if err := os.WriteFile(filepath.Join(outside, "user@corp-secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "at@dir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	engine := testEngine(t)
	opts := testOptions(t, root)

	for _, command := range []string{
		"cat ../user@corp-secret.txt",
		"cat ./at@dir/../../secret.txt",
		"cat at@dir/../../user@corp-secret.txt",
		"cat " + filepath.ToSlash(filepath.Join(outside, "mail@host", "secret.txt")),
		"cat -o../secret.txt",
		"cat -C" + filepath.ToSlash(outside),
		"cat -Wl,-rpath,../secret.txt",
		"cat DESTDIR=../secret.txt",
		"cat --output=../secret.txt",
		"cat -C..",
		"cat -C~",
	} {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": command}), opts)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", command, err)
		}
		if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
			t.Fatalf("%s: outside path must be found: %s %q", command, res.Permission, res.Reason)
		}
	}

	denyOpts := opts
	denyOpts.OutsideWorkspace = ModeDeny
	res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": "cat ../user@corp-secret.txt"}), denyOpts)
	if err != nil || res.Permission != PermissionDeny {
		t.Fatalf("outside path with @ must deny under deny mode: %s %q err=%v", res.Permission, res.Reason, err)
	}

	if runtime.GOOS != "windows" {
		if err := os.MkdirAll(filepath.Join(outside, "dir"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(filepath.Join(outside, "dir"), filepath.Join(root, "link")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": "cat link/../mail@host/secret.txt"}), opts)
		if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
			t.Fatalf("symlink escape with @ must be found: %s %q err=%v", res.Permission, res.Reason, err)
		}
	}

	// Remotes, URLs, and inside paths with separators produce no finding.
	for _, command := range []string{
		"git clone git@github.com:org/repo.git",
		"git clone https://github.com/org/repo.git",
		"cat sub/a,b",
		"cat KEY=src/x",
		"cat -osrc/out.txt",
	} {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": command}), opts)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", command, err)
		}
		if strings.Contains(res.Reason, "outside the workspace") {
			t.Fatalf("%s: must not be flagged as outside: %s %q", command, res.Permission, res.Reason)
		}
	}
	res, err = Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": "cat sub/a,b"}), opts)
	if err != nil || res.Permission != PermissionAllow {
		t.Fatalf("inside path with comma must stay allowed: %s %q err=%v", res.Permission, res.Reason, err)
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

func TestEvaluateReviewFindingsStayClosed(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)

	// F1: git configuration overrides execute commands; never evaluated as plain git.
	for _, cmd := range []string{"git -c core.pager='cat config/.env' status", "git -c alias.zz='!touch MARK' zz", "git --exec-path=./src status"} {
		res, err := Evaluate(engine, bashInput(root, cmd), opts)
		if err != nil {
			t.Fatalf("%q: %v", cmd, err)
		}
		if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "cannot safely interpret") {
			t.Fatalf("%q: got %s %q", cmd, res.Permission, res.Reason)
		}
	}

	// F2: a failed cd leaves the real shell in the original directory.
	res, _ := Evaluate(engine, bashInput(root, "cd nope ; cat ../secret.txt"), opts)
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "outside the workspace") {
		t.Fatalf("failed cd then parent read: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, bashInput(root, "cd nope || cp secret.txt ../out"), opts)
	if res.Permission != PermissionAsk {
		t.Fatalf("cd || write outside: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, bashInput(root, "cd src && cat ../README.md"), opts)
	if res.Permission != PermissionAllow {
		t.Fatalf("cd && parent-of-subdir read stays inside: %s %q", res.Permission, res.Reason)
	}

	// F3: passthrough withholds the decision instead of allowing.
	pass := opts
	pass.OutsideWorkspace = ModePassthrough
	res, _ = Evaluate(engine, bashInput(root, "cat /etc/hostname"), pass)
	if !res.Passthrough() {
		t.Fatalf("passthrough with outside path must yield no decision, got %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, bashInput(root, "cat /etc/hostname && cat config/.env"), pass)
	if res.Permission != PermissionDeny {
		t.Fatalf("deny must still win under passthrough: %s %q", res.Permission, res.Reason)
	}
	res, _ = Evaluate(engine, bashInput(root, "cat /etc/hostname && git push origin main"), pass)
	if res.Permission != PermissionAsk {
		t.Fatalf("ask must beat passthrough: %s %q", res.Permission, res.Reason)
	}

	// Ambiguous MCP names are not guessed.
	res, _ = Evaluate(engine, toolInput(root, "mcp__srv__get__thing", map[string]any{}), opts)
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, "ambiguous MCP tool name") {
		t.Fatalf("ambiguous mcp name: %s %q", res.Permission, res.Reason)
	}
}

func TestSanitizeIDKeepsDistinctRawIDsDistinct(t *testing.T) {
	a := sanitizeID("toolu 01", "hook")
	b := sanitizeID("toolu_01", "hook")
	c := sanitizeID("toolu-01", "hook")
	if a == b || a == c {
		t.Fatalf("sanitized ids collide: %q %q %q", a, b, c)
	}
	if b != "toolu_01" || c != "toolu-01" {
		t.Fatalf("clean ids must be unchanged: %q %q", b, c)
	}
	if sanitizeID("   ", "hook") != "hook" {
		t.Fatal("empty id must use the fallback")
	}
}

func TestSafeDevProfileTuningKeepsDeniesAndCutsNoise(t *testing.T) {
	root := newWorkspace(t)
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bundle, err := launcher.EmbeddedProfileBundle("safe-dev")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	engine := policy.NewEngine(bundle)
	opts := testOptions(t, root)
	opts.BundleLabel = "profile safe-dev"
	cases := []struct {
		command string
		want    string
		reason  string
	}{
		{"rm -rf ~/", PermissionDeny, "catastrophic-delete"},
		{"rm -rf ~/*", PermissionDeny, "catastrophic-delete"},
		{"rm -rf /", PermissionDeny, "catastrophic-delete"},
		{"rm -rf ../*", PermissionDeny, "catastrophic-delete"},
		{"rmdir /s /q E:\\", PermissionDeny, "catastrophic-delete"},
		{"rm -rf ~/.cache/e2e-build", PermissionAsk, "outside the workspace"},
		{"rm -rf /tmp/build", PermissionAsk, "outside the workspace"},
		{"rm -rf tests/ patches/", PermissionAsk, "requires confirmation"},
		{"git remote -v", PermissionAllow, "git-readonly"},
		{"git status && git log --oneline -5 && git remote -v && git branch -vv", PermissionAllow, "git-readonly"},
		{"git commit --amend -m x", PermissionAsk, "requires confirmation"},
		{"git push --force-with-lease=main origin main", PermissionAsk, "requires confirmation"},
		{"git add -A && git commit -m 'fix'", PermissionAllow, "git-workflow"},
		{"printenv BUILD_DIR", PermissionAllow, "local-inspection"},
		{"env", PermissionAllow, "local-inspection"},
		{"du -sh .", PermissionAllow, "local-inspection"},
		{"cargo test --workspace", PermissionAllow, "dev-toolchain"},
		{"yarn install && yarn build", PermissionAllow, "dev-toolchain"},
		{"mkdir -p build && cp -r src build/", PermissionAllow, "workspace-file-ops"},
		{"cp ~/.ssh/id_rsa .", PermissionDeny, "secret-file-args"},
		{"cp /etc/hostname .", PermissionAsk, "outside the workspace"},
		{"sudo apt-get install jq", PermissionAsk, "cannot safely interpret"},
	}
	for _, tc := range cases {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": tc.command}), opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.command, err)
		}
		if res.Permission != tc.want || !strings.Contains(res.Reason, tc.reason) {
			t.Errorf("%s: got %s %q, want %s mentioning %q", tc.command, res.Permission, res.Reason, tc.want, tc.reason)
		}
	}
	res, err := Evaluate(engine, toolInput(root, "Write", map[string]any{"file_path": "config/.env", "content": "X=1"}), opts)
	if err != nil || res.Permission != PermissionAsk || !strings.Contains(res.Reason, "requires confirmation") {
		t.Fatalf("writing a secrets file must ask: %s %q err=%v", res.Permission, res.Reason, err)
	}
	res, err = Evaluate(engine, toolInput(root, "Read", map[string]any{"file_path": "config/.env"}), opts)
	if err != nil || res.Permission != PermissionDeny {
		t.Fatalf("reading a secrets file must stay denied: %s %q err=%v", res.Permission, res.Reason, err)
	}
}

func TestEvaluateDecidesRedirectionsAndPrintOnlyExpansions(t *testing.T) {
	root := newWorkspace(t)
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bundle, err := launcher.EmbeddedProfileBundle("safe-dev")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	engine := policy.NewEngine(bundle)
	opts := testOptions(t, root)
	opts.BundleLabel = "profile safe-dev"
	cases := []struct {
		command string
		want    string
		reason  string
	}{
		{"go test ./... > out.txt", PermissionAllow, "fs.write out.txt"},
		{"go test ./... 2>&1 | tee build.log", PermissionAllow, "allows"},
		{"sort < src/main.go", PermissionAllow, "fs.read src/main.go"},
		{"cat src/main.go > /tmp/copy.go", PermissionAsk, "outside the workspace"},
		{"echo hi > ~/.bashrc", PermissionAsk, "outside the workspace"},
		{"sort < ../secret.txt", PermissionAsk, "outside the workspace"},
		{"echo KEY=1 > config/.env", PermissionAsk, "requires confirmation"},
		{"echo $HOME", PermissionAllow, "allows"},
		{`echo "BUILD_DIR=[$BUILD_DIR]"`, PermissionAllow, "allows"},
		{"printenv $NAME", PermissionAllow, "allows"},
		{"cat <<< hello", PermissionAllow, "allows"},
		{"rm -rf $DIR", PermissionAsk, "cannot safely interpret"},
		{`bash -c "echo $X"`, PermissionAsk, "cannot safely interpret"},
		{"cat > \"$OUT\"", PermissionAsk, "cannot safely interpret"},
	}
	for _, tc := range cases {
		res, err := Evaluate(engine, toolInput(root, "Bash", map[string]any{"command": tc.command}), opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.command, err)
		}
		if res.Permission != tc.want || !strings.Contains(res.Reason, tc.reason) {
			t.Errorf("%s: got %s %q, want %s mentioning %q", tc.command, res.Permission, res.Reason, tc.want, tc.reason)
		}
	}
}
