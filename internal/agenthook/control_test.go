package agenthook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/policy"
)

// controlBundleYAML allows the file tools and commands the control cases
// use, so an ask or deny can only come from the control-file check.
const controlBundleYAML = `version: v1
rules:
  - id: allow-file-commands
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["cat", "**"]
        - ["tail", "**"]
        - ["sed", "**"]
        - ["tee", "**"]
        - ["cp", "**"]
        - ["mv", "**"]
        - ["dd", "**"]
        - ["echo", "**"]
        - ["rm", "**"]
  - id: allow-workspace-read
    action_type: fs.read
    resource: file://workspace/**
    decision: ALLOW
  - id: allow-workspace-write
    action_type: fs.write
    resource: file://workspace/**
    decision: ALLOW
`

const (
	controlConfigReason = "could change the hook's own configuration"
	controlAuditReason  = "may not write the hook's audit log"
)

func controlEngine(t *testing.T) *policy.Engine {
	t.Helper()
	bundle, err := policy.LoadBundleBytes([]byte(controlBundleYAML), "control.yaml")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return policy.NewEngine(bundle)
}

func controlWorkspace(t *testing.T) string {
	t.Helper()
	root := newWorkspace(t)
	for _, dir := range []string{".claude", ".codex", ".nomos", "policy", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for _, file := range []string{".claude/settings.json", ".codex/hooks.json", ".nomos/claude-code-hook.jsonl", "policy/bundle.yaml"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file)), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func TestControlFilesInCommands(t *testing.T) {
	root := controlWorkspace(t)
	engine := controlEngine(t)
	opts := testOptions(t, root)
	cases := []struct {
		name    string
		command string
		want    string
		reason  string
	}{
		{name: "sed -i on the project settings", command: "sed -i s/nomos/x/ .claude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "copy over the local settings", command: "cp other.json .claude/settings.local.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "bare name after cd into .claude", command: "cd .claude && tee settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "doubled separator", command: "cp other.json .claude//settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "dot segments", command: "cp other.json ./.claude/./settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "parent segments", command: "cp other.json src/../.claude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "glob star", command: "cp other.json .claude/*.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "glob question mark in a directory", command: "sed -i s/a/b/ .c?aude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "glob class", command: "sed -i s/a/b/ .claude/[s]ettings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "other case", command: "cp other.json .CLAUDE/Settings.JSON", want: PermissionAsk, reason: controlConfigReason},
		{name: "move the settings directory", command: "mv .claude .claude.bak", want: PermissionAsk, reason: controlConfigReason},
		{name: "move the codex directory", command: "mv .codex elsewhere", want: PermissionAsk, reason: controlConfigReason},
		{name: "dd output operand", command: "dd if=other.toml of=.codex/config.toml", want: PermissionAsk, reason: controlConfigReason},
		{name: "command on the audit log asks", command: "tee .nomos/claude-code-hook.jsonl", want: PermissionAsk, reason: controlConfigReason},
		{name: "command on the audit directory", command: "rm -rf .nomos", want: PermissionAsk, reason: controlConfigReason},
		{name: "bare name after cd into .nomos", command: "cd .nomos && tee claude-code-hook.jsonl", want: PermissionAsk, reason: controlConfigReason},
		{name: "dotfile glob in the audit directory", command: "rm -f .nomos/.*", want: PermissionAsk, reason: controlConfigReason},
		{name: "redirection into the audit log is denied", command: "echo x > .nomos/claude-code-hook.jsonl", want: PermissionDeny, reason: controlAuditReason},
		{name: "append redirection into the audit log is denied", command: "echo x >> .nomos/claude-code-hook.jsonl", want: PermissionDeny, reason: controlAuditReason},
		{name: "redirection into the settings asks", command: `echo '{}' > .claude/settings.json`, want: PermissionAsk, reason: controlConfigReason},
		{name: "home settings", command: "cp other.json ~/.claude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "read-only program by path is not trusted", command: "/bin/cat .claude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "read-only name started by relative path is not trusted", command: "./cat .claude/settings.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "cat reads the settings", command: "cat .claude/settings.json", want: PermissionAllow},
		{name: "tail reads the audit log", command: "tail -n 5 .nomos/claude-code-hook.jsonl", want: PermissionAllow},
		{name: "star does not match dotfiles", command: "cp * dst/", want: PermissionAllow},
		{name: "other files under .claude", command: "cp review.md .claude/commands/review.md", want: PermissionAllow},
		{name: "settings.json outside .claude", command: "sed -i s/a/b/ settings.json", want: PermissionAllow},
		{name: "similar directory name", command: "cp other.json .claudex/settings.json", want: PermissionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(engine, bashInput(root, tc.command), opts)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Permission != tc.want {
				t.Fatalf("permission = %q, want %q (reason %q)", res.Permission, tc.want, res.Reason)
			}
			if tc.reason != "" && !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", res.Reason, tc.reason)
			}
		})
	}
}

func TestControlFilesFromSubdirectory(t *testing.T) {
	root := controlWorkspace(t)
	in := bashInput(filepath.Join(root, "src"), "cp other.json ../.claude/settings.json")
	res, err := Evaluate(controlEngine(t), in, testOptions(t, root))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Permission != PermissionAsk || !strings.Contains(res.Reason, controlConfigReason) {
		t.Fatalf("got %q (%q), want ask on the control file", res.Permission, res.Reason)
	}
}

func TestControlFilesInFileTools(t *testing.T) {
	root := controlWorkspace(t)
	engine := controlEngine(t)
	opts := testOptions(t, root)
	opts.ControlFiles = []string{filepath.Join(root, "policy", "bundle.yaml")}
	opts.AuditFiles = []string{filepath.Join(root, "logs", "audit.jsonl")}
	home := opts.HomeDir
	cases := []struct {
		name   string
		tool   string
		path   string
		opts   func(Options) Options
		want   string
		reason string
	}{
		{name: "write the project settings", tool: "Write", path: filepath.Join(root, ".claude", "settings.json"), want: PermissionAsk, reason: controlConfigReason},
		{name: "edit the local settings", tool: "Edit", path: ".claude/settings.local.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "multi-edit the codex hooks", tool: "MultiEdit", path: ".codex/hooks.json", want: PermissionAsk, reason: controlConfigReason},
		{name: "edit the codex config", tool: "Edit", path: ".codex/config.toml", want: PermissionAsk, reason: controlConfigReason},
		{name: "edit the policy bundle", tool: "Edit", path: "policy/bundle.yaml", want: PermissionAsk, reason: controlConfigReason},
		{name: "write the default audit log", tool: "Write", path: ".nomos/claude-code-hook.jsonl", want: PermissionDeny, reason: controlAuditReason},
		{name: "write anything under .nomos", tool: "Write", path: ".nomos/notes.txt", want: PermissionDeny, reason: controlAuditReason},
		{name: "write .nomos in another case", tool: "Write", path: ".NOMOS/claude-code-hook.jsonl", want: PermissionDeny, reason: controlAuditReason},
		{name: "write a custom audit log", tool: "Write", path: "logs/audit.jsonl", want: PermissionDeny, reason: controlAuditReason},
		{name: "home settings under passthrough", tool: "Write", path: filepath.Join(home, ".claude", "settings.json"), opts: func(o Options) Options { o.OutsideWorkspace = ModePassthrough; return o }, want: PermissionAsk, reason: controlConfigReason},
		{name: "home codex hooks under passthrough", tool: "Edit", path: "~/.codex/hooks.json", opts: func(o Options) Options { o.OutsideWorkspace = ModePassthrough; return o }, want: PermissionAsk, reason: controlConfigReason},
		{name: "read the settings", tool: "Read", path: ".claude/settings.json", want: PermissionAllow},
		{name: "read the audit log", tool: "Read", path: ".nomos/claude-code-hook.jsonl", want: PermissionAllow},
		{name: "write a slash command", tool: "Write", path: ".claude/commands/review.md", want: PermissionAllow},
		{name: "write next to the custom audit log", tool: "Write", path: "logs/other.txt", want: PermissionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			if tc.opts != nil {
				o = tc.opts(o)
			}
			res, err := Evaluate(engine, toolInput(root, tc.tool, map[string]any{"file_path": tc.path}), o)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Permission != tc.want {
				t.Fatalf("permission = %q, want %q (reason %q)", res.Permission, tc.want, res.Reason)
			}
			if tc.reason != "" && !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", res.Reason, tc.reason)
			}
		})
	}
	t.Run("commands on configured files", func(t *testing.T) {
		for command, want := range map[string]string{
			"rm -rf policy":                  PermissionAsk,
			"sed -i s/x/y/ logs/audit.jsonl": PermissionAsk,
			"cat policy/bundle.yaml":         PermissionAllow,
		} {
			res, err := Evaluate(engine, bashInput(root, command), opts)
			if err != nil {
				t.Fatalf("evaluate %q: %v", command, err)
			}
			if res.Permission != want {
				t.Fatalf("%q: permission = %q, want %q (reason %q)", command, res.Permission, want, res.Reason)
			}
		}
	})
}

func TestControlFilesThroughSymlinks(t *testing.T) {
	root := controlWorkspace(t)
	if err := os.Symlink(filepath.Join(".claude", "settings.json"), filepath.Join(root, "link.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(".claude", filepath.Join(root, "cfg")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	engine := controlEngine(t)
	opts := testOptions(t, root)
	for _, in := range []Input{
		bashInput(root, "tee link.json"),
		bashInput(root, "cp other.json cfg/settings.json"),
		toolInput(root, "Write", map[string]any{"file_path": "link.json"}),
		toolInput(root, "Edit", map[string]any{"file_path": "cfg/settings.local.json"}),
	} {
		res, err := Evaluate(engine, in, opts)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Permission != PermissionAsk || !strings.Contains(res.Reason, controlConfigReason) {
			t.Fatalf("%s %s: got %q (%q), want ask on the control file", in.ToolName, in.ToolInput, res.Permission, res.Reason)
		}
	}
}

func TestControlFilesInCodexPatches(t *testing.T) {
	root := controlWorkspace(t)
	engine := controlEngine(t)
	opts := testOptions(t, root)
	for _, tc := range []struct {
		patch string
		want  string
	}{
		{patch: "*** Begin Patch\n*** Update File: .codex/hooks.json\n@@\n-{}\n+{\"hooks\":{}}\n*** End Patch\n", want: PermissionAsk},
		{patch: "*** Begin Patch\n*** Delete File: .codex/config.toml\n*** End Patch\n", want: PermissionAsk},
		{patch: "*** Begin Patch\n*** Update File: notes.md\n*** Move to: .claude/settings.json\n@@\n-a\n+b\n*** End Patch\n", want: PermissionAsk},
		{patch: "*** Begin Patch\n*** Add File: .nomos/codex-hook.jsonl\n+{}\n*** End Patch\n", want: PermissionDeny},
		{patch: "*** Begin Patch\n*** Add File: src/main.go\n+package main\n*** End Patch\n", want: PermissionAllow},
	} {
		in := toolInput(root, CodexToolApplyPatch, map[string]any{"command": tc.patch})
		res, err := EvaluateMapping(engine, in, MapCodexToolCall(in, opts), opts)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Permission != tc.want {
			t.Fatalf("patch %q: permission = %q, want %q (reason %q)", tc.patch, res.Permission, tc.want, res.Reason)
		}
	}
}

func TestGlobComponentFollowsBash(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", ".claude", false},
		{".*", ".claude", true},
		{".c*", ".claude", true},
		{"*.json", "settings.json", true},
		{"[s]ettings.json", "settings.json", true},
		{"[!x]ettings.json", "settings.json", true},
		{"[!s]ettings.json", "settings.json", false},
		{"[", "[", true},
		{"[", "settings.json", false},
		{"proj[1]", "proj[1]", true},
	}
	for _, tc := range cases {
		if got := globComponent(tc.pattern, tc.name); got != tc.want {
			t.Errorf("globComponent(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}
