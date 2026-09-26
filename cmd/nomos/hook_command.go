package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/agenthook"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/launcher"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

const (
	hookExitOK    = 0
	hookExitError = 2 // Claude Code blocks the tool call on exit 2.

	defaultHookAuditFile = "claude-code-hook.jsonl"
)

func runHook(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		writeHelpText(os.Stderr, hookHelpText())
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	switch args[0] {
	case "claude-code":
		os.Exit(runClaudeCodeHook(args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
	case "codex":
		os.Exit(runCodexHook(args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
	default:
		writeHelpText(os.Stderr, hookHelpText())
		os.Exit(2)
	}
}

type claudeHookFlags struct {
	bundlePath       string
	profile          string
	workspace        string
	principal        string
	agent            string
	environment      string
	onDefault        string
	onUnsupported    string
	outsideWorkspace string
	auditPath        string
	install          bool
	settingsPath     string
	matcher          string
	hookCommand      string
	timeoutSeconds   int
	includeMCP       bool
	printSettings    bool
	simulate         bool
	tool             string
	input            string
	command          string
	verifyAudit      bool
	replayPath       string
	replayTranscript bool
	transcriptsDir   string
	format           string
	top              int
	showAsks         bool
	postToolUse      bool
	suggest          bool
}

// runClaudeCodeHook implements `nomos hook claude-code`. It returns the
// process exit code: 0 with a decision (or no output for passthrough), and 2
// for any failure, which makes Claude Code block the tool call.
func runClaudeCodeHook(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	var f claudeHookFlags
	fs := flag.NewFlagSet("hook claude-code", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&f.bundlePath, "p", "", "policy bundle path")
	fs.StringVar(&f.profile, "profile", "", "embedded profile: safe-dev|ci-strict|prod-locked (default safe-dev)")
	fs.StringVar(&f.workspace, "workspace", "", "workspace root (default CLAUDE_PROJECT_DIR, then the hook's cwd)")
	fs.StringVar(&f.principal, "principal", "developer", "principal recorded on evaluated actions")
	fs.StringVar(&f.agent, "agent", "claude-code", "agent recorded on evaluated actions")
	fs.StringVar(&f.environment, "environment", "local", "environment recorded on evaluated actions")
	fs.StringVar(&f.onDefault, "on-default", agenthook.ModeAsk, "when no rule matches: ask|deny")
	fs.StringVar(&f.onUnsupported, "on-unsupported", agenthook.ModeAsk, "when shell syntax cannot be interpreted: ask|deny")
	fs.StringVar(&f.outsideWorkspace, "outside-workspace", agenthook.ModeAsk, "when a path resolves outside the workspace: ask|deny|passthrough")
	fs.StringVar(&f.auditPath, "audit", "", "hash-chained JSONL audit file (default <workspace>/.nomos/"+defaultHookAuditFile+"; \"none\" disables)")
	fs.BoolVar(&f.install, "install", false, "register the hook in a Claude Code settings file and exit")
	fs.StringVar(&f.settingsPath, "settings", "", "settings file for --install (default <workspace>/.claude/settings.json)")
	fs.StringVar(&f.matcher, "matcher", agenthook.DefaultMatcher, "tool matcher for --install/--print-settings")
	fs.StringVar(&f.hookCommand, "hook-command", "", "command to register (default: nomos hook claude-code with the same policy flags)")
	fs.IntVar(&f.timeoutSeconds, "timeout", agenthook.DefaultTimeoutSeconds, "hook timeout in seconds for --install/--print-settings")
	fs.BoolVar(&f.includeMCP, "mcp", false, "also match MCP tools (mcp__*) in --install/--print-settings")
	fs.BoolVar(&f.printSettings, "print-settings", false, "print the settings.json hooks block and exit")
	fs.BoolVar(&f.simulate, "simulate", false, "evaluate --tool/--input or --command instead of reading hook JSON from stdin")
	fs.StringVar(&f.tool, "tool", "", "tool name for --simulate (default Bash when --command is set)")
	fs.StringVar(&f.input, "input", "", "tool_input JSON for --simulate")
	fs.StringVar(&f.command, "command", "", "shell command for --simulate (Bash tool)")
	fs.BoolVar(&f.verifyAudit, "verify-audit", false, "verify the audit file's hash chain and exit")
	fs.StringVar(&f.replayPath, "replay", "", "replay recorded tool calls from a file (\"-\" for stdin) and report the decisions")
	fs.BoolVar(&f.replayTranscript, "replay-transcripts", false, "replay every Claude Code transcript under --transcripts-dir")
	fs.StringVar(&f.transcriptsDir, "transcripts-dir", "", "transcript directory for --replay-transcripts (default ~/.claude/projects)")
	fs.StringVar(&f.format, "format", "text", "report format for --replay: text|json")
	fs.IntVar(&f.top, "top", 25, "list length for programs and commands in a replay report")
	fs.BoolVar(&f.showAsks, "show-asks", false, "list every call that would ask in a replay report")
	fs.BoolVar(&f.postToolUse, "post-tool-use", true, "also register a PostToolUse hook so approved calls are recorded for --suggest")
	fs.BoolVar(&f.suggest, "suggest", false, "propose allow rules from the audit log's asked-then-approved calls and exit")
	fs.Usage = func() { writeHelpText(fs.Output(), hookHelpText()) }
	if err := fs.Parse(args); err != nil {
		return hookExitError
	}
	if f.bundlePath != "" && f.profile != "" {
		fmt.Fprintln(stderr, "hook: --policy-bundle and --profile are mutually exclusive")
		return hookExitError
	}
	if f.bundlePath != "" {
		abs, err := filepath.Abs(f.bundlePath)
		if err != nil {
			fmt.Fprintf(stderr, "hook: resolve policy bundle: %v\n", err)
			return hookExitError
		}
		f.bundlePath = abs
	}

	if f.printSettings || f.install {
		return runClaudeCodeHookSetup(f, stdout, stderr, getenv)
	}
	if f.verifyAudit {
		root, err := resolveHookWorkspace(f.workspace, "", getenv)
		if err != nil {
			fmt.Fprintf(stderr, "hook: %v\n", err)
			return hookExitError
		}
		path := hookAuditPath(f.auditPath, root)
		if path == "" {
			fmt.Fprintln(stderr, "hook: --audit none has nothing to verify")
			return hookExitError
		}
		count, err := audit.VerifyFileChain(path)
		if err != nil {
			fmt.Fprintf(stderr, "hook: audit chain verification failed after %d events: %v\n", count, err)
			return 1
		}
		fmt.Fprintf(stdout, "verified %d chained audit events in %s\n", count, path)
		return hookExitOK
	}

	if f.suggest {
		return runClaudeCodeHookSuggest(f, stdout, stderr, getenv)
	}
	engine, label, err := resolveHookEngine(f.bundlePath, f.profile)
	if err != nil {
		fmt.Fprintf(stderr, "hook: load policy: %v\n", err)
		return hookExitError
	}
	if f.replayPath != "" || f.replayTranscript {
		return runClaudeCodeHookReplay(f, engine, label, stdin, stdout, stderr, getenv)
	}

	var in agenthook.Input
	if f.simulate {
		in, err = simulatedHookInput(f)
	} else {
		in, err = agenthook.ParseInput(stdin)
	}
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	root, err := resolveHookWorkspace(f.workspace, in.Cwd, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	if in.Cwd == "" {
		in.Cwd = root
	}
	opts := agenthook.Options{
		WorkspaceRoot:    root,
		Identity:         identity.VerifiedIdentity{Principal: f.principal, Agent: f.agent, Environment: f.environment},
		OnDefaultDeny:    f.onDefault,
		OnUnsupported:    f.onUnsupported,
		OutsideWorkspace: f.outsideWorkspace,
		BundleLabel:      label,
		HomeDir:          agenthook.DefaultHomeDir(),
	}
	if in.HookEventName == "PostToolUse" {
		// The call already ran; record that so --suggest can learn which
		// asks were approved. PostToolUse hooks cannot block, so nothing is
		// printed and a failure only costs the record.
		if path := hookAuditPath(f.auditPath, root); path != "" {
			recorder, err := audit.NewFileChainRecorder(path, redact.DefaultRedactor())
			if err != nil {
				fmt.Fprintf(stderr, "hook: audit: %v\n", err)
				return hookExitError
			}
			if err := recorder.WriteEvent(agenthook.CompletionEvent(in, opts, time.Now())); err != nil {
				fmt.Fprintf(stderr, "hook: audit write failed: %v\n", err)
				return hookExitError
			}
		}
		return hookExitOK
	}
	res, err := agenthook.Evaluate(engine, in, opts)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	if path := hookAuditPath(f.auditPath, root); path != "" && !res.Passthrough() {
		recorder, err := audit.NewFileChainRecorder(path, redact.DefaultRedactor())
		if err != nil {
			fmt.Fprintf(stderr, "hook: audit: %v\n", err)
			return hookExitError
		}
		for _, event := range agenthook.AuditEvents(in, res, opts, time.Now()) {
			if err := recorder.WriteEvent(event); err != nil {
				fmt.Fprintf(stderr, "hook: audit write failed, blocking the tool call: %v\n", err)
				return hookExitError
			}
		}
	}
	if f.simulate {
		if res.Passthrough() {
			fmt.Fprintf(stderr, "decision: passthrough (Nomos has no opinion; Claude Code's own permission flow applies)\n")
		} else {
			fmt.Fprintf(stderr, "decision: %s\nreason: %s\n", res.Permission, res.Reason)
		}
	}
	out, err := res.HookOutput()
	if err != nil {
		fmt.Fprintf(stderr, "hook: encode output: %v\n", err)
		return hookExitError
	}
	if out != nil {
		fmt.Fprintln(stdout, string(out))
	}
	return hookExitOK
}

// runClaudeCodeHookReplay evaluates recorded tool calls with the live
// pipeline and prints a report. It writes no audit and runs nothing.
func runClaudeCodeHookReplay(f claudeHookFlags, engine *policy.Engine, label string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if f.format != "text" && f.format != "json" {
		fmt.Fprintf(stderr, "hook: --format must be text or json\n")
		return hookExitError
	}
	root, err := resolveHookWorkspace(f.workspace, "", getenv)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	var records []agenthook.ReplayRecord
	var errs []string
	if f.replayPath != "" {
		var r io.Reader = stdin
		source := "stdin"
		if f.replayPath != "-" {
			file, err := os.Open(f.replayPath)
			if err != nil {
				fmt.Fprintf(stderr, "hook: replay: %v\n", err)
				return hookExitError
			}
			defer file.Close()
			r, source = file, f.replayPath
		}
		records, errs = agenthook.ReadReplayFile(r, source)
	}
	if f.replayTranscript {
		dir := strings.TrimSpace(f.transcriptsDir)
		if dir == "" {
			home := agenthook.DefaultHomeDir()
			if home == "" {
				fmt.Fprintln(stderr, "hook: --transcripts-dir is required when the home directory is unknown")
				return hookExitError
			}
			dir = filepath.Join(home, ".claude", "projects")
		}
		recs, readErrs, err := agenthook.ReadTranscriptDir(dir)
		if err != nil {
			fmt.Fprintf(stderr, "hook: replay transcripts: %v\n", err)
			return hookExitError
		}
		records = append(records, recs...)
		errs = append(errs, readErrs...)
	}
	opts := agenthook.Options{
		WorkspaceRoot:    root,
		Identity:         identity.VerifiedIdentity{Principal: f.principal, Agent: f.agent, Environment: f.environment},
		OnDefaultDeny:    f.onDefault,
		OnUnsupported:    f.onUnsupported,
		OutsideWorkspace: f.outsideWorkspace,
		BundleLabel:      label,
		HomeDir:          agenthook.DefaultHomeDir(),
	}
	report, err := agenthook.Replay(engine, records, opts, agenthook.ReplayOptions{IncludeMCP: f.includeMCP, KeepAsks: f.showAsks || f.format == "json", Top: f.top})
	if err != nil {
		fmt.Fprintf(stderr, "hook: replay: %v\n", err)
		return hookExitError
	}
	report.Errors = append(errs, report.Errors...)
	if f.format == "json" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "hook: encode report: %v\n", err)
			return hookExitError
		}
		fmt.Fprintln(stdout, string(data))
		return hookExitOK
	}
	fmt.Fprint(stdout, report.Text())
	if f.showAsks {
		fmt.Fprintln(stdout, "calls that would ask:")
		for _, a := range report.Asks {
			fmt.Fprintf(stdout, "  %-20s %s: %s\n", a.Class, a.Tool, a.Command)
		}
	}
	return hookExitOK
}

// runClaudeCodeHookSuggest proposes allow rules from the audit log. It
// reads only; the user decides what to add to the bundle.
func runClaudeCodeHookSuggest(f claudeHookFlags, stdout, stderr io.Writer, getenv func(string) string) int {
	if f.format != "text" && f.format != "json" {
		fmt.Fprintf(stderr, "hook: --format must be text or json\n")
		return hookExitError
	}
	root, err := resolveHookWorkspace(f.workspace, "", getenv)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	path := hookAuditPath(f.auditPath, root)
	if path == "" {
		fmt.Fprintln(stderr, "hook: --audit none leaves nothing to learn from")
		return hookExitError
	}
	file, err := agenthook.ReadAuditFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "hook: suggest: %v\n", err)
		return hookExitError
	}
	defer file.Close()
	report, err := agenthook.Suggest(file, f.top)
	if err != nil {
		fmt.Fprintf(stderr, "hook: suggest: %v\n", err)
		return hookExitError
	}
	if f.format == "json" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "hook: encode report: %v\n", err)
			return hookExitError
		}
		fmt.Fprintln(stdout, string(data))
		return hookExitOK
	}
	fmt.Fprint(stdout, report.Text(path))
	return hookExitOK
}

func runClaudeCodeHookSetup(f claudeHookFlags, stdout, stderr io.Writer, getenv func(string) string) int {
	command := strings.TrimSpace(f.hookCommand)
	if command == "" {
		command = "nomos hook claude-code"
		switch {
		case f.bundlePath != "":
			command += " -p " + shellQuote(f.bundlePath)
		case f.profile != "":
			command += " --profile " + shellQuote(f.profile)
		}
		if f.onDefault != agenthook.ModeAsk {
			command += " --on-default " + shellQuote(f.onDefault)
		}
		if f.onUnsupported != agenthook.ModeAsk {
			command += " --on-unsupported " + shellQuote(f.onUnsupported)
		}
		if f.outsideWorkspace != agenthook.ModeAsk {
			command += " --outside-workspace " + shellQuote(f.outsideWorkspace)
		}
		if f.auditPath != "" {
			command += " --audit " + shellQuote(f.auditPath)
		}
	}
	matcher := f.matcher
	if f.includeMCP && !strings.Contains(matcher, "mcp__") {
		matcher += "|mcp__.*"
	}
	if f.printSettings {
		data, err := json.MarshalIndent(agenthook.SettingsSnippet(command, matcher, f.timeoutSeconds, f.postToolUse), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "hook: %v\n", err)
			return hookExitError
		}
		fmt.Fprintln(stdout, string(data))
		return hookExitOK
	}
	root, err := resolveHookWorkspace(f.workspace, "", getenv)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	settingsPath := f.settingsPath
	if settingsPath == "" {
		settingsPath = filepath.Join(root, ".claude", "settings.json")
	}
	changed, err := agenthook.InstallHook(settingsPath, command, matcher, f.timeoutSeconds, f.postToolUse)
	if err != nil {
		fmt.Fprintf(stderr, "hook: install: %v\n", err)
		return hookExitError
	}
	if changed {
		fmt.Fprintf(stdout, "installed Nomos PreToolUse hook in %s\n  matcher: %s\n  command: %s\n", settingsPath, matcher, command)
	} else {
		fmt.Fprintf(stdout, "Nomos PreToolUse hook is already registered in %s\n", settingsPath)
	}
	return hookExitOK
}

func resolveHookEngine(bundlePath, profile string) (*policy.Engine, string, error) {
	if bundlePath != "" {
		bundle, err := policy.LoadBundles([]string{bundlePath})
		if err != nil {
			return nil, "", err
		}
		return policy.NewEngine(bundle), filepath.Base(bundlePath), nil
	}
	if profile == "" {
		profile = "safe-dev"
	}
	bundle, err := launcher.EmbeddedProfileBundle(profile)
	if err != nil {
		return nil, "", err
	}
	return policy.NewEngine(bundle), "profile " + profile, nil
}

// resolveHookWorkspace picks the Claude Code hook's workspace root: the
// flag, then CLAUDE_PROJECT_DIR (which Claude Code sets for its hooks), then
// the hook input's cwd, then the process working directory.
func resolveHookWorkspace(flagValue, inputCwd string, getenv func(string) string) (string, error) {
	projectDir := ""
	if getenv != nil {
		projectDir = getenv("CLAUDE_PROJECT_DIR")
	}
	return resolveWorkspaceRoot(flagValue, projectDir, inputCwd)
}

// resolveWorkspaceRoot returns the first non-empty candidate as an absolute,
// cleaned path, falling back to the process working directory.
func resolveWorkspaceRoot(flagValue, envValue, inputCwd string) (string, error) {
	candidate := strings.TrimSpace(flagValue)
	if candidate == "" {
		candidate = strings.TrimSpace(envValue)
	}
	if candidate == "" {
		candidate = strings.TrimSpace(inputCwd)
	}
	if candidate == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("determine workspace: %w", err)
		}
		candidate = wd
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	return filepath.Clean(abs), nil
}

// shellQuote quotes one argument for the POSIX shell that Claude Code and
// Codex run hook commands through (`sh -c`, `$SHELL -lc`), so a bundle or
// audit path with a space or a quote survives the round trip. Plain
// tokens are returned unchanged to keep generated commands readable.
func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	plain := true
	for _, r := range arg {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_@%+=:,./-", r):
		default:
			plain = false
		}
		if !plain {
			break
		}
	}
	if plain {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

func hookAuditPath(flagValue, root string) string {
	value := strings.TrimSpace(flagValue)
	if strings.EqualFold(value, "none") {
		return ""
	}
	if value == "" {
		return filepath.Join(root, ".nomos", defaultHookAuditFile)
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(root, value)
}

func simulatedHookInput(f claudeHookFlags) (agenthook.Input, error) {
	tool := strings.TrimSpace(f.tool)
	raw := strings.TrimSpace(f.input)
	if f.command != "" {
		if tool == "" {
			tool = "Bash"
		}
		if raw != "" {
			return agenthook.Input{}, errors.New("--command and --input are mutually exclusive")
		}
		data, err := json.Marshal(map[string]any{"command": f.command})
		if err != nil {
			return agenthook.Input{}, err
		}
		raw = string(data)
	}
	if tool == "" {
		return agenthook.Input{}, errors.New("--simulate requires --tool (or --command)")
	}
	if raw == "" {
		raw = "{}"
	}
	if !json.Valid([]byte(raw)) {
		return agenthook.Input{}, errors.New("--input must be a JSON object")
	}
	return agenthook.Input{
		SessionID:      "simulate",
		HookEventName:  "PreToolUse",
		PermissionMode: "simulate",
		ToolName:       tool,
		ToolInput:      json.RawMessage(raw),
		ToolUseID:      "simulate",
	}, nil
}

func hookHelpText() string {
	return "usage: nomos hook claude-code [flags]   (nomos hook codex --help for the Codex hook)\n" +
		"Claude Code PreToolUse hook: decides native Bash/Read/Write/Edit/WebFetch (and optionally MCP) tool calls\n" +
		"with a Nomos policy. Reads the hook JSON on stdin and prints allow/deny/ask JSON. Exit code 2 blocks the call.\n\n" +
		"policy:\n" +
		"  -p, --policy-bundle <path>   policy bundle (YAML or JSON)\n" +
		"      --profile <name>         embedded profile safe-dev|ci-strict|prod-locked (default safe-dev)\n" +
		"      --workspace <dir>        workspace root (default CLAUDE_PROJECT_DIR, then the hook's cwd)\n" +
		"      --on-default ask|deny    no matching rule (default ask)\n" +
		"      --on-unsupported ask|deny\n" +
		"                               shell syntax Nomos will not interpret (default ask)\n" +
		"      --outside-workspace ask|deny|passthrough\n" +
		"                               path resolves outside the workspace (default ask)\n" +
		"      --audit <path|none>      hash-chained JSONL log (default .nomos/" + defaultHookAuditFile + ")\n" +
		"      --principal/--agent/--environment\n" +
		"                               identity recorded on actions (default developer/claude-code/local)\n\n" +
		"setup:\n" +
		"      --install [--settings <path>] [--matcher <regex>] [--mcp] [--timeout <s>] [--hook-command <cmd>]\n" +
		"      --print-settings         print the hooks block instead of writing it\n" +
		"      --verify-audit           verify the audit file's hash chain\n" +
		"      --suggest [--top <n>]    propose allow rules from asked-then-approved calls in the audit log\n" +
		"      --post-tool-use=false    do not register the PostToolUse hook that records approved calls\n\n" +
		"try it:\n" +
		"      --simulate --command \"rm -rf ~/\"\n" +
		"      --simulate --tool Read --input '{\"file_path\":\".env\"}'\n\n" +
		"measure before you install:\n" +
		"      --replay <file|->        replay recorded calls (corpus JSONL, hook input JSON, transcript lines, or plain commands)\n" +
		"      --replay-transcripts [--transcripts-dir <dir>]\n" +
		"                               replay your own Claude Code transcripts (default ~/.claude/projects), read-only\n" +
		"      --format text|json --top <n> --show-asks\n\n" +
		"examples:\n" +
		"  nomos hook claude-code --install --profile safe-dev\n" +
		"  nomos hook claude-code --simulate --profile ci-strict --command \"git push --force\"\n" +
		"  nomos hook claude-code --replay-transcripts --profile safe-dev\n"
}
