package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/agenthook"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

const defaultCodexAuditFile = "codex-hook.jsonl"

type codexHookFlags struct {
	bundlePath             string
	profile                string
	workspace              string
	principal              string
	agent                  string
	environment            string
	onDefault              string
	onUnsupported          string
	outsideWorkspace       string
	ask                    string
	permissionRequestAllow bool
	auditPath              string
	install                bool
	hooksFile              string
	matcher                string
	hookCommand            string
	timeoutSeconds         int
	includeMCP             bool
	permissionRequest      bool
	printHooks             bool
	simulate               bool
	tool                   string
	input                  string
	command                string
	event                  string
	permissionMode         string
	verifyAudit            bool
}

// runCodexHook implements `nomos hook codex`, the Codex PreToolUse and
// PermissionRequest hook. It exits 0 with a decision or with no output when
// Codex's own flow should continue, and 2 with a reason on stderr for any
// failure, which Codex treats as a block for PreToolUse.
//
// Unlike the Claude Code hook, the workspace root never comes from
// CLAUDE_PROJECT_DIR: Codex replays the environment it was started from into
// its hooks, so a Codex launched from a Claude Code session would otherwise
// inherit a foreign root.
func runCodexHook(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	_ = getenv // the Codex hook reads no environment variables (see above)
	var f codexHookFlags
	fs := flag.NewFlagSet("hook codex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.bundlePath, "policy-bundle", "", "policy bundle path")
	fs.StringVar(&f.bundlePath, "p", "", "policy bundle path")
	fs.StringVar(&f.profile, "profile", "", "embedded profile: safe-dev|ci-strict|prod-locked (default safe-dev)")
	fs.StringVar(&f.workspace, "workspace", "", "workspace root (default the hook's cwd)")
	fs.StringVar(&f.principal, "principal", "developer", "principal recorded on evaluated actions")
	fs.StringVar(&f.agent, "agent", "codex", "agent recorded on evaluated actions")
	fs.StringVar(&f.environment, "environment", "local", "environment recorded on evaluated actions")
	fs.StringVar(&f.onDefault, "on-default", agenthook.ModeAsk, "when no rule matches: ask|deny")
	fs.StringVar(&f.onUnsupported, "on-unsupported", agenthook.ModeAsk, "when shell syntax cannot be interpreted: ask|deny")
	fs.StringVar(&f.outsideWorkspace, "outside-workspace", agenthook.ModeAsk, "when a path resolves outside the workspace: ask|deny|passthrough")
	fs.StringVar(&f.ask, "ask", agenthook.AskDeny, "what an ask means in PreToolUse, which cannot ask: deny|passthrough")
	fs.BoolVar(&f.permissionRequestAllow, "permission-request-allow", false, "let an allow answer a plain PermissionRequest so Codex skips its prompt (never for escalations or with approvals disabled)")
	fs.StringVar(&f.auditPath, "audit", "", "hash-chained JSONL audit file (default <workspace>/.nomos/"+defaultCodexAuditFile+"; \"none\" disables)")
	fs.BoolVar(&f.install, "install", false, "register the hook in a Codex hooks.json file and exit")
	fs.StringVar(&f.hooksFile, "hooks-file", "", "hooks file for --install (default <workspace>/.codex/hooks.json)")
	fs.StringVar(&f.matcher, "matcher", agenthook.CodexDefaultMatcher, "tool matcher for --install/--print-hooks")
	fs.StringVar(&f.hookCommand, "hook-command", "", "command to register (default: nomos hook codex with the same policy flags)")
	fs.IntVar(&f.timeoutSeconds, "timeout", agenthook.DefaultTimeoutSeconds, "hook timeout in seconds for --install/--print-hooks")
	fs.BoolVar(&f.includeMCP, "mcp", false, "also match MCP tools (mcp__*) in --install/--print-hooks")
	fs.BoolVar(&f.permissionRequest, "permission-request", true, "also register a PermissionRequest hook so denies hold in the approval path")
	fs.BoolVar(&f.printHooks, "print-hooks", false, "print the hooks.json document and exit")
	fs.BoolVar(&f.simulate, "simulate", false, "evaluate --tool/--input or --command instead of reading hook JSON from stdin")
	fs.StringVar(&f.tool, "tool", "", "tool name for --simulate (default Bash when --command is set)")
	fs.StringVar(&f.input, "input", "", "tool_input JSON for --simulate")
	fs.StringVar(&f.command, "command", "", "shell command for --simulate (Bash tool)")
	fs.StringVar(&f.event, "event", agenthook.CodexEventPreToolUse, "hook event for --simulate: PreToolUse|PermissionRequest")
	fs.StringVar(&f.permissionMode, "permission-mode", agenthook.CodexDefaultMode, "permission_mode for --simulate: default|bypassPermissions")
	fs.BoolVar(&f.verifyAudit, "verify-audit", false, "verify the audit file's hash chain and exit")
	fs.Usage = func() { writeHelpText(fs.Output(), codexHookHelpText()) }
	if err := fs.Parse(args); err != nil {
		return hookExitError
	}
	if f.bundlePath != "" && f.profile != "" {
		fmt.Fprintln(stderr, "hook: --policy-bundle and --profile are mutually exclusive")
		return hookExitError
	}
	if f.ask != agenthook.AskDeny && f.ask != agenthook.AskPassthrough {
		fmt.Fprintln(stderr, "hook: --ask must be deny or passthrough")
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
	if f.printHooks || f.install {
		return runCodexHookSetup(f, stdout, stderr)
	}
	if f.verifyAudit {
		root, err := resolveWorkspaceRoot(f.workspace, "", "")
		if err != nil {
			fmt.Fprintf(stderr, "hook: %v\n", err)
			return hookExitError
		}
		path := codexAuditPath(f.auditPath, root)
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

	engine, label, err := resolveHookEngine(f.bundlePath, f.profile)
	if err != nil {
		fmt.Fprintf(stderr, "hook: load policy: %v\n", err)
		return hookExitError
	}
	var in agenthook.Input
	if f.simulate {
		in, err = simulatedCodexInput(f)
	} else {
		in, err = agenthook.ParseInput(stdin)
	}
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	if in.HookEventName == "" {
		in.HookEventName = agenthook.CodexEventPreToolUse
	}
	if in.HookEventName != agenthook.CodexEventPreToolUse && in.HookEventName != agenthook.CodexEventPermissionRequest {
		// Another lifecycle event was routed here (a hooks.json that
		// registers the command for PostToolUse, for example). It carries
		// nothing to decide, so nothing is evaluated, audited, or printed.
		return hookExitOK
	}
	root, err := resolveWorkspaceRoot(f.workspace, "", in.Cwd)
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
	copts := agenthook.CodexOptions{Ask: f.ask, PermissionRequestAllow: f.permissionRequestAllow}
	res, err := agenthook.EvaluateMapping(engine, in, agenthook.MapCodexToolCall(in, opts), opts)
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	// The wire decision is computed before the audit so the record shows
	// what Codex received, not only the pre-translation permission.
	var wire agenthook.CodexWire
	switch in.HookEventName {
	case agenthook.CodexEventPreToolUse:
		wire, err = agenthook.CodexPreToolUseOutput(res, in.PermissionMode, copts)
	case agenthook.CodexEventPermissionRequest:
		wire, err = agenthook.CodexPermissionRequestOutput(res, in, copts)
	}
	if err != nil {
		fmt.Fprintf(stderr, "hook: encode output: %v\n", err)
		return hookExitError
	}
	if path := codexAuditPath(f.auditPath, root); path != "" && !res.Passthrough() {
		recorder, err := audit.NewFileChainRecorder(path, redact.DefaultRedactor())
		if err != nil {
			fmt.Fprintf(stderr, "hook: audit: %v\n", err)
			return hookExitError
		}
		for _, event := range agenthook.CodexAuditEvents(in, res, wire, copts, opts, time.Now()) {
			if err := recorder.WriteEvent(event); err != nil {
				fmt.Fprintf(stderr, "hook: audit write failed, blocking the tool call: %v\n", err)
				return hookExitError
			}
		}
	}
	if f.simulate {
		decision := res.Permission
		if res.Passthrough() {
			decision = "passthrough (Nomos has no opinion)"
		}
		fmt.Fprintf(stderr, "decision: %s\nreason: %s\n%s: %s\n", decision, res.Reason, in.HookEventName, codexSimulatedEffect(in, res, wire, copts))
	}
	if wire.Output != nil {
		fmt.Fprintln(stdout, string(wire.Output))
	}
	return hookExitOK
}

// codexSimulatedEffect explains, for --simulate, what Codex does with the
// hook's output in the given event and permission mode.
func codexSimulatedEffect(in agenthook.Input, res agenthook.Result, wire agenthook.CodexWire, copts agenthook.CodexOptions) string {
	if wire.Output != nil {
		return "Codex receives " + string(wire.Output)
	}
	switch in.HookEventName {
	case agenthook.CodexEventPermissionRequest:
		switch {
		case res.Permission == agenthook.PermissionAllow && !copts.PermissionRequestAllow:
			return "no output; Codex's reviewer or the user decides (--permission-request-allow would answer allow for a plain prompt)"
		case res.Permission == agenthook.PermissionAllow && in.PermissionMode == agenthook.CodexBypassMode:
			return "no output; approvals are disabled, so Codex's own reviewer decides"
		case res.Permission == agenthook.PermissionAllow:
			return "no output; this request is an escalation (sandbox or network), so Codex's reviewer or the user decides"
		default:
			return "no output; Codex's reviewer or the user decides"
		}
	default:
		if res.Permission == agenthook.PermissionAsk {
			if in.PermissionMode == agenthook.CodexBypassMode {
				return "no output; approvals are disabled, so the call runs without a prompt (--ask deny would block it)"
			}
			return "no output; in Codex's usual on-request mode the call runs sandboxed without a prompt (--ask deny would block it)"
		}
		return "no output; Codex's own flow continues"
	}
}

func runCodexHookSetup(f codexHookFlags, stdout, stderr io.Writer) int {
	command := strings.TrimSpace(f.hookCommand)
	if command == "" {
		command = "nomos hook codex"
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
		if f.ask != agenthook.AskDeny {
			command += " --ask " + shellQuote(f.ask)
		}
		if f.permissionRequestAllow {
			command += " --permission-request-allow"
		}
		if f.auditPath != "" {
			command += " --audit " + shellQuote(f.auditPath)
		}
	}
	matcher := agenthook.CodexMatcher(f.matcher, f.includeMCP)
	if f.printHooks {
		data, err := json.MarshalIndent(agenthook.CodexHooksSnippet(command, matcher, f.timeoutSeconds, f.permissionRequest), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "hook: %v\n", err)
			return hookExitError
		}
		fmt.Fprintln(stdout, string(data))
		return hookExitOK
	}
	root, err := resolveWorkspaceRoot(f.workspace, "", "")
	if err != nil {
		fmt.Fprintf(stderr, "hook: %v\n", err)
		return hookExitError
	}
	path := f.hooksFile
	if path == "" {
		path = filepath.Join(root, ".codex", "hooks.json")
	}
	changed, err := agenthook.InstallCodexHooks(path, command, matcher, f.timeoutSeconds, f.permissionRequest)
	if err != nil {
		fmt.Fprintf(stderr, "hook: install: %v\n", err)
		return hookExitError
	}
	if changed {
		fmt.Fprintf(stdout, "registered %q in %s\n  matcher: %s\n", command, path, matcher)
		fmt.Fprintln(stdout, "Codex asks you to trust project hooks the first time it starts here; accept the Nomos entry to activate it.")
	} else {
		fmt.Fprintf(stdout, "Nomos hook already registered in %s\n", path)
	}
	return hookExitOK
}

func codexAuditPath(flagValue, root string) string {
	if strings.EqualFold(strings.TrimSpace(flagValue), "none") {
		return ""
	}
	if strings.TrimSpace(flagValue) != "" {
		if filepath.IsAbs(flagValue) {
			return flagValue
		}
		return filepath.Join(root, flagValue)
	}
	return filepath.Join(root, ".nomos", defaultCodexAuditFile)
}

func simulatedCodexInput(f codexHookFlags) (agenthook.Input, error) {
	if f.event != agenthook.CodexEventPreToolUse && f.event != agenthook.CodexEventPermissionRequest {
		return agenthook.Input{}, fmt.Errorf("--event must be %s or %s", agenthook.CodexEventPreToolUse, agenthook.CodexEventPermissionRequest)
	}
	if f.permissionMode != agenthook.CodexDefaultMode && f.permissionMode != agenthook.CodexBypassMode {
		return agenthook.Input{}, fmt.Errorf("--permission-mode must be %s or %s", agenthook.CodexDefaultMode, agenthook.CodexBypassMode)
	}
	tool := strings.TrimSpace(f.tool)
	var input json.RawMessage
	switch {
	case strings.TrimSpace(f.command) != "" && strings.TrimSpace(f.input) != "":
		return agenthook.Input{}, fmt.Errorf("--command and --input are mutually exclusive")
	case strings.TrimSpace(f.command) != "":
		if tool == "" {
			tool = "Bash"
		}
		data, err := json.Marshal(map[string]string{"command": f.command})
		if err != nil {
			return agenthook.Input{}, err
		}
		input = data
	case strings.TrimSpace(f.input) != "":
		if tool == "" {
			return agenthook.Input{}, fmt.Errorf("--tool is required with --input")
		}
		if !json.Valid([]byte(f.input)) {
			return agenthook.Input{}, fmt.Errorf("--input must be valid JSON")
		}
		input = json.RawMessage(f.input)
	default:
		return agenthook.Input{}, fmt.Errorf("--simulate needs --command or --tool with --input")
	}
	return agenthook.Input{
		SessionID:      "simulate",
		TurnID:         "simulate",
		HookEventName:  f.event,
		PermissionMode: f.permissionMode,
		ToolName:       tool,
		ToolInput:      input,
		ToolUseID:      "simulate",
	}, nil
}

func codexHookHelpText() string {
	return "usage: nomos hook codex [flags]\n" +
		"Codex PreToolUse and PermissionRequest hook: decides Bash, apply_patch (and optionally MCP) tool calls\n" +
		"with a Nomos policy. Reads the hook JSON on stdin. A deny is printed where Codex acts on it: as a\n" +
		"PreToolUse deny and as a PermissionRequest deny. Codex's PreToolUse cannot ask, so an ask becomes a deny\n" +
		"(--ask passthrough leaves the call to Codex, which in its usual on-request mode runs it sandboxed without\n" +
		"a prompt). An allow prints nothing; --permission-request-allow lets it answer plain PermissionRequest\n" +
		"prompts. Exit code 2 blocks the call.\n\n" +
		"policy:\n" +
		"  -p, --policy-bundle <path>   policy bundle (YAML or JSON)\n" +
		"      --profile <name>         embedded profile safe-dev|ci-strict|prod-locked (default safe-dev)\n" +
		"      --workspace <dir>        workspace root (default the hook's cwd; CLAUDE_PROJECT_DIR is ignored)\n" +
		"      --on-default ask|deny    no matching rule (default ask)\n" +
		"      --on-unsupported ask|deny\n" +
		"                               shell syntax Nomos will not interpret (default ask)\n" +
		"      --outside-workspace ask|deny|passthrough\n" +
		"                               path resolves outside the workspace (default ask)\n" +
		"      --ask deny|passthrough   what an ask means in PreToolUse, which cannot ask (default deny)\n" +
		"      --permission-request-allow\n" +
		"                               answer plain PermissionRequest prompts with allow (default off; never for\n" +
		"                               sandbox or network escalations, never with approvals disabled)\n" +
		"      --audit <path|none>      hash-chained JSONL log (default .nomos/" + defaultCodexAuditFile + ")\n" +
		"      --principal/--agent/--environment\n" +
		"                               identity recorded on actions (default developer/codex/local)\n\n" +
		"setup:\n" +
		"      --install [--hooks-file <path>] [--matcher <regex>] [--mcp] [--timeout <s>] [--hook-command <cmd>] [--permission-request=false]\n" +
		"      --print-hooks            print the hooks.json document instead of writing it\n" +
		"      --verify-audit           verify the audit file's hash chain\n\n" +
		"try it:\n" +
		"      --simulate --command \"rm -rf ~/\" [--permission-mode bypassPermissions] [--event PermissionRequest]\n" +
		"      --simulate --tool apply_patch --input '{\"command\":\"*** Begin Patch\\n*** Update File: config/.env\\n@@\\n-a\\n+b\\n*** End Patch\"}'\n\n" +
		"examples:\n" +
		"  nomos hook codex --install --profile safe-dev\n" +
		"  nomos hook codex --simulate --profile ci-strict --command \"git push --force\" --permission-mode bypassPermissions\n"
}
