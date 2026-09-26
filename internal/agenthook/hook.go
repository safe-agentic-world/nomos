// Package agenthook adapts coding-agent tool-call hooks to Nomos policy
// decisions. The first adapter targets Claude Code's PreToolUse hook: it reads
// the hook's JSON from stdin, maps the native tool call (Bash, Read, Write,
// Edit, WebFetch, MCP tools) to normalized Nomos actions, evaluates them with
// the deny-wins policy engine, and answers with the hook's allow / deny / ask
// JSON. Anything the adapter cannot interpret safely is never auto-allowed.
package agenthook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

// Hook permission decisions, as Claude Code expects them.
const (
	PermissionAllow = "allow"
	PermissionDeny  = "deny"
	PermissionAsk   = "ask"
)

// Modes for situations the policy cannot decide on its own.
const (
	ModeAsk         = "ask"
	ModeDeny        = "deny"
	ModePassthrough = "passthrough"
)

// Finding kinds.
const (
	FindingUnsupported      = "unsupported_shell"
	FindingOutsideWorkspace = "outside_workspace"
	FindingNormalization    = "normalization_error"
)

const (
	maxInputBytes    = 1 << 20
	argvSummaryBytes = 256
	hookEventType    = "hook.decision"
	hookEventName    = "PreToolUse"
)

var idSanitizer = regexp.MustCompile(`[^A-Za-z0-9._:-]`)

// Options configures one evaluation.
type Options struct {
	// WorkspaceRoot is the absolute directory that file resources are
	// expressed relative to. Paths that resolve outside it cannot be
	// represented as file://workspace/... resources.
	WorkspaceRoot string
	// Identity is attached to every action; the hook has no authenticated
	// caller, so it comes from operator configuration.
	Identity identity.VerifiedIdentity
	// OnDefaultDeny decides what a deny_by_default policy outcome means to
	// the agent: ModeAsk (the user is prompted) or ModeDeny.
	OnDefaultDeny string
	// OnUnsupported decides what unparseable or unsafe shell syntax means:
	// ModeAsk or ModeDeny.
	OnUnsupported string
	// OutsideWorkspace decides what a path outside WorkspaceRoot means:
	// ModeAsk, ModeDeny, or ModePassthrough (leave it to the agent's own
	// permission system).
	OutsideWorkspace string
	// BundleLabel names the policy in reasons and audit records.
	BundleLabel string
	// HomeDir resolves a leading `~`. Empty means unknown, which counts as
	// outside the workspace.
	HomeDir string
}

// Input is the subset of the PreToolUse payload the adapter uses.
type Input struct {
	SessionID      string          `json:"session_id"`
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	PermissionMode string          `json:"permission_mode"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

// MappedAction is one normalized Nomos action derived from a tool call.
type MappedAction struct {
	ActionType string
	Resource   string
	Params     map[string]any
	Summary    string
	// Original is the command name as written, when it was normalized.
	Original string
}

// Finding is something the adapter refused to interpret or resolve.
type Finding struct {
	Kind   string
	Detail string
}

// Mapping is the result of translating one tool call.
type Mapping struct {
	Actions     []MappedAction
	Findings    []Finding
	Passthrough bool
}

// Outcome is the policy decision for one mapped action.
type Outcome struct {
	Action     MappedAction
	Decision   policy.Decision
	ParamsHash string
}

// Result is the complete hook decision.
type Result struct {
	// Permission is allow, deny, ask, or empty for passthrough.
	Permission string
	Reason     string
	Mapping    Mapping
	Outcomes   []Outcome
}

// Passthrough reports whether the adapter has no decision for this call.
func (r Result) Passthrough() bool { return r.Permission == "" }

// ParseInput decodes the hook payload. Unknown fields are ignored because
// Claude Code adds fields over time; missing tool_name is an error.
func ParseInput(r io.Reader) (Input, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return Input{}, err
	}
	if len(data) > maxInputBytes {
		return Input{}, errors.New("hook input exceeds 1 MiB")
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		return Input{}, fmt.Errorf("decode hook input: %w", err)
	}
	if strings.TrimSpace(in.ToolName) == "" {
		return Input{}, errors.New("hook input has no tool_name")
	}
	if len(in.ToolInput) == 0 {
		in.ToolInput = json.RawMessage(`{}`)
	}
	return in, nil
}

// Evaluate maps the tool call and decides it against engine.
func Evaluate(engine *policy.Engine, in Input, opts Options) (Result, error) {
	if engine == nil {
		return Result{}, errors.New("policy engine is required")
	}
	if err := opts.validate(); err != nil {
		return Result{}, err
	}
	return EvaluateMapping(engine, in, MapToolCall(in, opts), opts)
}

// EvaluateMapping decides an already mapped tool call. Adapters for other
// harnesses map their own tool shapes and share this evaluation.
func EvaluateMapping(engine *policy.Engine, in Input, mapping Mapping, opts Options) (Result, error) {
	if engine == nil {
		return Result{}, errors.New("policy engine is required")
	}
	if err := opts.validate(); err != nil {
		return Result{}, err
	}
	res := Result{Mapping: mapping}
	if mapping.Passthrough {
		return res, nil
	}
	for _, act := range mapping.Actions {
		outcome, err := evaluateAction(engine, in, act, opts)
		if err != nil {
			mapping.Findings = append(mapping.Findings, Finding{Kind: FindingNormalization, Detail: act.Summary + ": " + err.Error()})
			res.Mapping = mapping
			continue
		}
		res.Outcomes = append(res.Outcomes, outcome)
	}
	res.Permission, res.Reason = aggregate(res.Outcomes, res.Mapping.Findings, opts)
	return res, nil
}

func (o Options) validate() error {
	if !filepath.IsAbs(o.WorkspaceRoot) {
		return errors.New("workspace root must be an absolute path")
	}
	if o.Identity.Principal == "" || o.Identity.Agent == "" || o.Identity.Environment == "" {
		return errors.New("principal, agent, and environment are required")
	}
	switch o.OnDefaultDeny {
	case ModeAsk, ModeDeny:
	default:
		return fmt.Errorf("invalid on-default mode %q", o.OnDefaultDeny)
	}
	switch o.OnUnsupported {
	case ModeAsk, ModeDeny:
	default:
		return fmt.Errorf("invalid on-unsupported mode %q", o.OnUnsupported)
	}
	switch o.OutsideWorkspace {
	case ModeAsk, ModeDeny, ModePassthrough:
	default:
		return fmt.Errorf("invalid outside-workspace mode %q", o.OutsideWorkspace)
	}
	return nil
}

// MapToolCall translates a tool call into Nomos actions and findings.
func MapToolCall(in Input, opts Options) Mapping {
	var params map[string]any
	if err := json.Unmarshal(in.ToolInput, &params); err != nil || params == nil {
		params = map[string]any{}
	}
	switch in.ToolName {
	case "Bash", "PowerShell":
		command, _ := params["command"].(string)
		return mapShell(command, in, opts)
	case "Read":
		return mapFile("fs.read", firstString(params, "file_path", "path"), in, opts)
	case "Write", "Edit", "MultiEdit":
		return mapFile("fs.write", firstString(params, "file_path", "path"), in, opts)
	case "NotebookEdit":
		return mapFile("fs.write", firstString(params, "notebook_path", "file_path", "path"), in, opts)
	case "WebFetch":
		rawURL, _ := params["url"].(string)
		return mapURL(rawURL)
	}
	if strings.HasPrefix(in.ToolName, "mcp__") {
		return mapMCP(in.ToolName, params)
	}
	return Mapping{Passthrough: true}
}

func firstString(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mapShell(command string, in Input, opts Options) Mapping {
	var m Mapping
	if strings.TrimSpace(command) == "" {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "empty command"})
		return m
	}
	list := SplitShellCommand(command)
	for _, u := range list.Unsupported {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: u.Reason + " near " + strconvQuote(u.Snippet)})
	}
	for _, target := range list.PathTargets {
		if class, resolved := classifyPath(target, "", in, opts); class == pathOutside {
			m.Findings = append(m.Findings, Finding{Kind: FindingOutsideWorkspace, Detail: "working directory " + strconvQuote(resolved)})
		}
	}
	for _, cmd := range list.Commands {
		for _, tok := range cmd.Argv[1:] {
		candidates:
			for _, value := range pathCandidates(tok) {
				for _, cwd := range cmd.Cwds {
					if class, resolved := classifyPath(value, cwd, in, opts); class == pathOutside {
						m.Findings = append(m.Findings, Finding{Kind: FindingOutsideWorkspace, Detail: "argument " + strconvQuote(tok) + " resolves to " + strconvQuote(resolved)})
						break candidates
					}
				}
			}
		}
		for _, r := range cmd.Redirects {
			m.merge(mapRedirect(r, cmd, in, opts))
		}
		params := map[string]any{"argv": toAnySlice(cmd.Argv), "cwd": filepath.ToSlash(cmd.Cwd)}
		m.Actions = append(m.Actions, MappedAction{
			ActionType: "process.exec",
			Resource:   "file://workspace/",
			Params:     params,
			Summary:    "process.exec " + summarizeArgv(cmd.Argv),
			Original:   cmd.Original,
		})
	}
	if len(m.Actions) == 0 && len(m.Findings) == 0 {
		// Only builtins such as `cd` that do nothing on their own.
		m.Passthrough = true
	}
	return m
}

// merge appends another mapping's actions and findings.
func (m *Mapping) merge(other Mapping) {
	m.Actions = append(m.Actions, other.Actions...)
	m.Findings = append(m.Findings, other.Findings...)
}

// mapRedirect turns a file redirection into the fs.read or fs.write it
// performs, resolved against every working directory the command may run
// in; a target outside the workspace is a finding like any other path.
func mapRedirect(r Redirect, cmd SimpleCommand, in Input, opts Options) Mapping {
	var m Mapping
	actionType := "fs.read"
	if r.Kind == "write" {
		actionType = "fs.write"
	}
	var rel string
	for i, cwd := range cmd.Cwds {
		class, resolved := classifyPath(r.Target, cwd, in, opts)
		switch class {
		case pathOutside:
			if opts.OutsideWorkspace == ModePassthrough {
				m.Passthrough = true
				return m
			}
			m.Findings = append(m.Findings, Finding{Kind: FindingOutsideWorkspace, Detail: "redirection " + strconvQuote(r.Target) + " resolves to " + strconvQuote(resolved)})
			return m
		case pathUnknown:
			m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "cannot resolve redirection target " + strconvQuote(r.Target)})
			return m
		}
		if i == 0 {
			rel = resolved
		}
	}
	resource := "file://workspace/" + escapePathSegments(rel)
	if rel == "." || rel == "" {
		resource = "file://workspace/"
	}
	m.Actions = append(m.Actions, MappedAction{
		ActionType: actionType,
		Resource:   resource,
		Params:     map[string]any{"path": filepath.ToSlash(rel), "redirect": r.Kind},
		Summary:    actionType + " " + filepath.ToSlash(rel) + " (redirection)",
	})
	return m
}

func mapFile(actionType, rawPath string, in Input, opts Options) Mapping {
	var m Mapping
	if strings.TrimSpace(rawPath) == "" {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "file tool call without a path"})
		return m
	}
	class, resolved := classifyPath(rawPath, "", in, opts)
	switch class {
	case pathOutside:
		if opts.OutsideWorkspace == ModePassthrough {
			m.Passthrough = true
			return m
		}
		m.Findings = append(m.Findings, Finding{Kind: FindingOutsideWorkspace, Detail: strconvQuote(resolved)})
		return m
	case pathUnknown:
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "cannot resolve path " + strconvQuote(rawPath)})
		return m
	}
	rel := resolved
	resource := "file://workspace/" + escapePathSegments(rel)
	if rel == "." || rel == "" {
		resource = "file://workspace/"
	}
	m.Actions = append(m.Actions, MappedAction{
		ActionType: actionType,
		Resource:   resource,
		Params:     map[string]any{"path": filepath.ToSlash(rel)},
		Summary:    actionType + " " + filepath.ToSlash(rel),
	})
	return m
}

func mapURL(rawURL string) Mapping {
	var m Mapping
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "unsupported fetch url " + strconvQuote(rawURL)})
		return m
	}
	if parsed.User != nil {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "fetch url with credentials"})
		return m
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	m.Actions = append(m.Actions, MappedAction{
		ActionType: "net.http_request",
		Resource:   "url://" + parsed.Host + path,
		Params:     map[string]any{"method": "GET"},
		Summary:    "net.http_request GET " + parsed.Host + path,
	})
	return m
}

func mapMCP(toolName string, params map[string]any) Mapping {
	var m Mapping
	rest := strings.TrimPrefix(toolName, "mcp__")
	parts := strings.SplitN(rest, "__", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "__") {
		m.Findings = append(m.Findings, Finding{Kind: FindingUnsupported, Detail: "ambiguous MCP tool name " + strconvQuote(toolName)})
		return m
	}
	server, tool := parts[0], parts[1]
	m.Actions = append(m.Actions, MappedAction{
		ActionType: "mcp.call",
		Resource:   "mcp://" + server + "/" + tool,
		Params: map[string]any{
			"upstream_server": server,
			"upstream_tool":   tool,
			"tool_arguments":  params,
		},
		Summary: "mcp.call " + server + "/" + tool,
	})
	return m
}

type pathClass int

const (
	pathInside pathClass = iota
	pathOutside
	pathUnknown
)

// classifyPath resolves raw against the command's effective cwd and reports
// whether it stays inside the workspace root. For inside paths it returns the
// workspace-relative path; otherwise the resolved absolute path.
func classifyPath(raw, cmdCwd string, in Input, opts Options) (pathClass, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return pathUnknown, raw
	}
	expand := func(p string) (string, bool) {
		if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
			if opts.HomeDir == "" {
				return "", false
			}
			return filepath.Join(opts.HomeDir, strings.TrimPrefix(p, "~")), true
		}
		if strings.HasPrefix(p, "~") {
			// ~user forms are not resolvable without lookups.
			return "", false
		}
		return p, true
	}
	base := in.Cwd
	if base == "" {
		base = opts.WorkspaceRoot
	}
	if cmdCwd != "" {
		expanded, ok := expand(cmdCwd)
		if !ok {
			return pathOutside, cmdCwd
		}
		if filepath.IsAbs(expanded) {
			base = expanded
		} else {
			// `cd` is logical in POSIX shells: `..` is applied to the
			// textual working directory, so the base is joined lexically.
			base = filepath.Join(base, expanded)
		}
	}
	expanded, ok := expand(raw)
	if !ok {
		return pathOutside, raw
	}
	// Two views of the argument are checked and the path is outside the
	// workspace when either escapes:
	//   - lexical: `..` collapsed first, then symlinks resolved (how a
	//     path-normalizing consumer such as an editor tool sees it);
	//   - physical: symlinks resolved component by component before each
	//     `..` (how the kernel opens it, so `link/../x` with `link`
	//     pointing outside the workspace lands outside).
	abs := expanded
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(base, abs)
	}
	abs = filepath.Clean(abs)
	root := filepath.Clean(opts.WorkspaceRoot)
	if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
		root = resolvedRoot
	}
	lexical := abs
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		lexical = resolved
	} else {
		// The path may not exist yet (a new file); resolve the deepest
		// existing ancestor so a symlinked parent cannot escape unnoticed.
		lexical = resolveExistingPrefix(abs)
	}
	physical := physicalPath(base, expanded)
	if outsideRoot(root, lexical) || outsideRoot(root, physical) {
		return pathOutside, abs
	}
	// Report the relative path from the unresolved cleaned path so the
	// resource keeps the name the agent used.
	if plainRel, err := filepath.Rel(filepath.Clean(opts.WorkspaceRoot), abs); err == nil && !strings.HasPrefix(plainRel, "..") {
		return pathInside, filepath.ToSlash(plainRel)
	}
	rel, _ := filepath.Rel(root, lexical)
	return pathInside, filepath.ToSlash(rel)
}

// outsideRoot reports whether candidate is not root itself or below it.
func outsideRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// physicalPath resolves target the way the kernel does when a process opens
// it: the base directory is resolved to its physical location first, then
// every component is applied in order, with symlinks resolved before a
// following `..` is taken. Components that do not exist yet are kept as
// written, which matches a fresh directory whose parent is its lexical one.
func physicalPath(base, target string) string {
	cur := base
	rest := target
	if filepath.IsAbs(target) {
		volume := filepath.VolumeName(target)
		cur = volume + string(filepath.Separator)
		rest = target[len(volume):]
	}
	if resolved, err := filepath.EvalSymlinks(cur); err == nil {
		cur = resolved
	} else {
		cur = resolveExistingPrefix(filepath.Clean(cur))
	}
	for _, comp := range strings.FieldsFunc(rest, isPathSeparator) {
		switch comp {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
		default:
			next := filepath.Join(cur, comp)
			if resolved, err := filepath.EvalSymlinks(next); err == nil {
				cur = resolved
			} else {
				cur = next
			}
		}
	}
	return cur
}

func isPathSeparator(r rune) bool {
	return r == '/' || r == filepath.Separator
}

func resolveExistingPrefix(abs string) string {
	dir := abs
	var suffix []string
	for {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			parts := append([]string{resolved}, reverse(suffix)...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs
		}
		suffix = append(suffix, filepath.Base(dir))
		dir = parent
	}
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

// pathCandidates extracts the filesystem paths an argv token may name.
// Option values are inspected whether they are separate (`-C /tmp`, handled
// as their own token), joined with `=` (`--prefix=/opt`), or glued to a
// short option (`-C/tmp`, `-o../out`), and values are additionally split on
// `,` and `=` so a path embedded in a flag or a variable assignment
// (`-Wl,-rpath,/usr/lib`, `DESTDIR=/tmp/x`) is still classified. Tokens
// containing `@` or `://` are not skipped: a URL or an scp-style remote is a
// relative name that resolves inside the workspace and yields no finding,
// while a real path that happens to contain `@` keeps its check.
func pathCandidates(tok string) []string {
	switch {
	case tok == "":
		return nil
	case strings.HasPrefix(tok, "--"):
		idx := strings.Index(tok, "=")
		if idx < 0 {
			return nil
		}
		return pathPieces(tok[idx+1:])
	case strings.HasPrefix(tok, "-"):
		if len(tok) <= 2 {
			return nil
		}
		return pathPieces(tok[2:])
	default:
		return pathPieces(tok)
	}
}

func pathPieces(value string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] || !pathShaped(p) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(value)
	if strings.ContainsAny(value, ",=") {
		for _, piece := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '=' }) {
			add(piece)
		}
	}
	return out
}

// pathShaped reports whether a token looks like a filesystem path: a
// relative or absolute name with a directory separator, a home reference,
// or a bare `.`/`..`. Windows spellings are accepted so a `..\` escape is
// classified on that platform; on POSIX a backslash is an ordinary byte and
// such a token resolves inside the workspace.
func pathShaped(tok string) bool {
	switch {
	case tok == ".", tok == "..", tok == "~":
		return true
	case strings.HasPrefix(tok, "/"), strings.HasPrefix(tok, "~"), strings.HasPrefix(tok, "./"), strings.HasPrefix(tok, "../"):
		return true
	case strings.HasPrefix(tok, "\\"), strings.HasPrefix(tok, ".\\"), strings.HasPrefix(tok, "..\\"):
		return true
	case strings.Contains(tok, "/"), strings.Contains(tok, "\\"):
		return true
	case len(tok) >= 2 && tok[1] == ':' && isASCIILetter(tok[0]):
		// Drive-relative or drive-absolute Windows path (`C:x`, `C:\x`).
		return true
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func evaluateAction(engine *policy.Engine, in Input, act MappedAction, opts Options) (Outcome, error) {
	params, err := json.Marshal(act.Params)
	if err != nil {
		return Outcome{}, err
	}
	req := action.Request{
		SchemaVersion: "v1",
		ActionID:      sanitizeID(in.ToolUseID, "hook"),
		ActionType:    act.ActionType,
		Resource:      act.Resource,
		Params:        params,
		TraceID:       sanitizeID(in.SessionID, "session"),
		Context:       action.Context{},
	}
	a, err := action.ToAction(req, opts.Identity)
	if err != nil {
		return Outcome{}, err
	}
	normalized, err := normalize.Action(a)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Action: act, Decision: engine.Evaluate(normalized), ParamsHash: normalized.ParamsHash}, nil
}

type contribution struct {
	level  int // 0 allow, 1 defer (no decision), 2 ask, 3 deny
	reason string
}

const (
	levelAllow = iota
	levelDefer
	levelAsk
	levelDeny
)

func aggregate(outcomes []Outcome, findings []Finding, opts Options) (string, string) {
	if len(outcomes) == 0 && len(findings) == 0 {
		return "", ""
	}
	label := opts.BundleLabel
	if label == "" {
		label = "policy"
	}
	contribs := make([]contribution, 0, len(outcomes)+len(findings))
	for _, o := range outcomes {
		rules := strings.Join(o.Decision.MatchedRuleIDs, ", ")
		switch o.Decision.Decision {
		case policy.DecisionDeny:
			if o.Decision.ReasonCode == "deny_by_default" {
				if opts.OnDefaultDeny == ModeDeny {
					contribs = append(contribs, contribution{levelDeny, fmt.Sprintf("no %s rule allows %s (deny by default)", label, o.Action.Summary)})
				} else {
					contribs = append(contribs, contribution{levelAsk, fmt.Sprintf("no %s rule allows %s; asking for confirmation", label, o.Action.Summary)})
				}
			} else {
				contribs = append(contribs, contribution{levelDeny, fmt.Sprintf("%s denies %s (rules: %s)", label, o.Action.Summary, rules)})
			}
		case policy.DecisionRequireApproval:
			contribs = append(contribs, contribution{levelAsk, fmt.Sprintf("%s requires confirmation for %s (rules: %s)", label, o.Action.Summary, rules)})
		case policy.DecisionAllow:
			contribs = append(contribs, contribution{levelAllow, fmt.Sprintf("%s allows %s (rules: %s)", label, o.Action.Summary, rules)})
		default:
			contribs = append(contribs, contribution{levelDeny, fmt.Sprintf("%s returned unknown decision %q for %s", label, o.Decision.Decision, o.Action.Summary)})
		}
	}
	for _, f := range findings {
		switch f.Kind {
		case FindingOutsideWorkspace:
			switch opts.OutsideWorkspace {
			case ModeDeny:
				contribs = append(contribs, contribution{levelDeny, "path outside the workspace: " + f.Detail})
			case ModeAsk:
				contribs = append(contribs, contribution{levelAsk, "path outside the workspace, asking for confirmation: " + f.Detail})
			default:
				// Passthrough: Nomos withholds its decision so the agent's
				// own permission flow applies. It never becomes an allow.
				contribs = append(contribs, contribution{levelDefer, "path outside the workspace, left to Claude Code: " + f.Detail})
			}
		default:
			if opts.OnUnsupported == ModeDeny {
				contribs = append(contribs, contribution{levelDeny, "cannot safely interpret the command: " + f.Detail})
			} else {
				contribs = append(contribs, contribution{levelAsk, "cannot safely interpret the command, asking for confirmation: " + f.Detail})
			}
		}
	}
	if len(contribs) == 0 {
		return "", ""
	}
	sort.SliceStable(contribs, func(i, j int) bool { return contribs[i].level > contribs[j].level })
	top := contribs[0]
	reasonParts := []string{}
	for _, c := range contribs {
		if c.level != top.level {
			break
		}
		reasonParts = append(reasonParts, c.reason)
		if len(reasonParts) == 3 {
			break
		}
	}
	reason := "Nomos: " + strings.Join(reasonParts, "; ")
	reason = redact.DefaultRedactor().RedactText(reason)
	switch top.level {
	case levelDeny:
		return PermissionDeny, reason
	case levelAsk:
		return PermissionAsk, reason
	case levelDefer:
		return "", ""
	default:
		return PermissionAllow, reason
	}
}

// HookOutput renders the PreToolUse decision JSON, or nil for passthrough.
func (r Result) HookOutput() ([]byte, error) {
	if r.Passthrough() {
		return nil, nil
	}
	payload := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            hookEventName,
			"permissionDecision":       r.Permission,
			"permissionDecisionReason": r.Reason,
		},
	}
	return json.Marshal(payload)
}

// eventName is the hook event recorded in audit: the harness's own name
// when the input carries one, else PreToolUse.
func eventName(in Input) string {
	if strings.TrimSpace(in.HookEventName) != "" {
		return in.HookEventName
	}
	return hookEventName
}

// AuditEvents builds one audit record per evaluated action and per finding.
func AuditEvents(in Input, res Result, opts Options, now time.Time) []audit.Event {
	base := func(index int) audit.Event {
		return audit.Event{
			SchemaVersion: "v1",
			Timestamp:     now.UTC(),
			EventType:     hookEventType,
			TraceID:       sanitizeID(in.SessionID, "session"),
			ActionID:      sanitizeID(in.ToolUseID, "hook") + fmt.Sprintf("-%d", index),
			Principal:     opts.Identity.Principal,
			Agent:         opts.Identity.Agent,
			Environment:   opts.Identity.Environment,
			ExecutorMetadata: map[string]any{
				"hook_event":      eventName(in),
				"hook_permission": res.Permission,
				"tool_name":       in.ToolName,
				"permission_mode": in.PermissionMode,
				"policy_label":    opts.BundleLabel,
			},
		}
	}
	events := make([]audit.Event, 0, len(res.Outcomes)+len(res.Mapping.Findings))
	index := 0
	for _, o := range res.Outcomes {
		ev := base(index)
		index++
		ev.ActionType = o.Action.ActionType
		ev.Resource = o.Action.Resource
		ev.ResourceNormalized = o.Action.Resource
		ev.ParamsHash = o.ParamsHash
		ev.Decision = o.Decision.Decision
		ev.Reason = o.Decision.ReasonCode
		ev.MatchedRuleIDs = append([]string{}, o.Decision.MatchedRuleIDs...)
		ev.PolicyBundleHash = o.Decision.PolicyBundleHash
		ev.ActionSummary = o.Action.Summary
		ev.ResultRedactedSummary = o.Action.Summary
		if o.Action.Original != "" {
			ev.ExecutorMetadata["command_as_written"] = o.Action.Original
		}
		events = append(events, ev)
	}
	for _, f := range res.Mapping.Findings {
		ev := base(index)
		index++
		ev.Decision = strings.ToUpper(f.Kind)
		ev.Reason = f.Kind
		ev.ActionSummary = in.ToolName + " " + f.Detail
		ev.ResultRedactedSummary = ev.ActionSummary
		events = append(events, ev)
	}
	return events
}

func sanitizeID(raw, fallback string) string {
	trimmed := strings.TrimSpace(raw)
	cleaned := idSanitizer.ReplaceAllString(trimmed, "-")
	cleaned = strings.TrimLeft(cleaned, "._:-")
	if cleaned == "" {
		return fallback
	}
	if len(cleaned) > 100 {
		cleaned = cleaned[:100]
	}
	if cleaned != trimmed {
		// Two raw IDs that sanitize to the same string must still yield
		// distinct audit IDs.
		sum := sha256.Sum256([]byte(trimmed))
		cleaned += "-" + hex.EncodeToString(sum[:4])
	}
	return cleaned
}

func summarizeArgv(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, a := range argv {
		quoted = append(quoted, strconvQuote(a))
	}
	s := "[" + strings.Join(quoted, " ") + "]"
	if len(s) > argvSummaryBytes {
		s = s[:argvSummaryBytes-3] + "..."
	}
	return s
}

func strconvQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `"?"`
	}
	return string(b)
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func escapePathSegments(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// DefaultHomeDir returns the current user's home directory or empty.
func DefaultHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
