package agenthook

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/policy"
)

// ReplayRecord is one recorded tool call to evaluate without a live agent.
type ReplayRecord struct {
	ToolName  string
	ToolInput json.RawMessage
	Cwd       string
	Source    string
}

// Ask classes explain why a replayed call would prompt.
const (
	AskUnsupportedShell = "unsupported_shell"
	AskOutsideWorkspace = "outside_workspace"
	AskApprovalRequired = "approval_required"
	AskNoMatchingRule   = "no_matching_rule"
)

// ReplayItem is one replayed call with its decision.
type ReplayItem struct {
	Tool       string `json:"tool"`
	Command    string `json:"command"`
	Source     string `json:"source,omitempty"`
	Permission string `json:"permission"`
	Class      string `json:"class,omitempty"`
	Reason     string `json:"reason"`
}

// ReplayReport summarizes a replay.
type ReplayReport struct {
	Policy      string          `json:"policy"`
	Records     int             `json:"records"`
	Skipped     int             `json:"skipped_tools"`
	Permissions map[string]int  `json:"permissions"`
	AskClasses  map[string]int  `json:"ask_classes"`
	AskPrograms []ReplayCount   `json:"ask_programs"`
	Denies      []ReplayItem    `json:"denies"`
	Asks        []ReplayItem    `json:"asks,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
	ByTool      map[string]int  `json:"by_tool"`
	TopCommands []ReplayCommand `json:"top_commands,omitempty"`
}

// ReplayCount is a program name with how many replayed calls it asked for.
type ReplayCount struct {
	Program string `json:"program"`
	Count   int    `json:"count"`
}

// ReplayCommand is a frequent command with its decision.
type ReplayCommand struct {
	Command    string `json:"command"`
	Count      int    `json:"count"`
	Permission string `json:"permission"`
}

// ReplayOptions tunes a replay.
type ReplayOptions struct {
	// Tools restricts which tool names are evaluated; nil means the default
	// matcher set. Names outside the set are counted as skipped.
	Tools []string
	// IncludeMCP also replays mcp__* tools.
	IncludeMCP bool
	// KeepAsks records every ask item, not only the aggregate counts.
	KeepAsks bool
	// Top bounds the ask-program and top-command lists (default 25).
	Top int
}

// ParseReplayLine turns one line of a replay file into records. Four
// shapes are accepted: a JSON object with "command" (a corpus line, with
// an optional "cwd"), a JSON object with "tool_name" and "tool_input" (the
// hook's own input), a Claude Code transcript line (an assistant message
// whose content holds tool_use blocks), and otherwise a plain shell
// command. Blank lines and lines starting with # yield nothing.
func ParseReplayLine(line string, source string) ([]ReplayRecord, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "{") {
		return []ReplayRecord{bashRecord(trimmed, "", source)}, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, fmt.Errorf("%s: not a JSON object: %w", source, err)
	}
	if raw, ok := obj["command"]; ok {
		var command string
		if err := json.Unmarshal(raw, &command); err != nil {
			return nil, fmt.Errorf("%s: command must be a string", source)
		}
		return []ReplayRecord{bashRecord(command, stringField(obj, "cwd"), source)}, nil
	}
	if raw, ok := obj["tool_name"]; ok {
		var name string
		if err := json.Unmarshal(raw, &name); err != nil || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%s: tool_name must be a non-empty string", source)
		}
		input := obj["tool_input"]
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		return []ReplayRecord{{ToolName: name, ToolInput: input, Cwd: stringField(obj, "cwd"), Source: source}}, nil
	}
	if raw, ok := obj["message"]; ok {
		return transcriptRecords(raw, stringField(obj, "cwd"), source)
	}
	if _, ok := obj["type"]; ok {
		// Transcript bookkeeping (summaries, attachments, progress) carries
		// no tool call.
		return nil, nil
	}
	return nil, fmt.Errorf("%s: unrecognized record shape", source)
}

func bashRecord(command, cwd, source string) ReplayRecord {
	input, _ := json.Marshal(map[string]string{"command": command})
	return ReplayRecord{ToolName: "Bash", ToolInput: input, Cwd: cwd, Source: source}
}

func stringField(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func transcriptRecords(raw json.RawMessage, cwd, source string) ([]ReplayRecord, error) {
	var msg struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, nil
	}
	if msg.Role != "assistant" || len(msg.Content) == 0 || msg.Content[0] != '[' {
		return nil, nil
	}
	var blocks []struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(msg.Content, &blocks); err != nil {
		return nil, nil
	}
	var out []ReplayRecord
	for _, b := range blocks {
		if b.Type != "tool_use" || strings.TrimSpace(b.Name) == "" {
			continue
		}
		input := b.Input
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		out = append(out, ReplayRecord{ToolName: b.Name, ToolInput: input, Cwd: cwd, Source: source})
	}
	return out, nil
}

// ReadReplayFile parses every line of r. Lines that cannot be parsed are
// reported in errs and skipped, so one bad line does not hide a whole file.
func ReadReplayFile(r io.Reader, source string) (records []ReplayRecord, errs []string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxInputBytes)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		recs, err := ParseReplayLine(scanner.Text(), fmt.Sprintf("%s:%d", source, lineNo))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		records = append(records, recs...)
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("%s: %v", source, err))
	}
	return records, errs
}

// ReadTranscriptDir parses every *.jsonl file under dir, which is how
// Claude Code stores session transcripts (~/.claude/projects/<project>/).
// Only tool_use blocks are extracted; nothing is written.
func ReadTranscriptDir(dir string) (records []ReplayRecord, errs []string, err error) {
	info, statErr := os.Stat(dir)
	if statErr != nil {
		return nil, nil, statErr
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, walkErr.Error())
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			errs = append(errs, openErr.Error())
			return nil
		}
		defer f.Close()
		recs, fileErrs := ReadReplayFile(f, path)
		records = append(records, recs...)
		errs = append(errs, fileErrs...)
		return nil
	})
	return records, errs, walkErr
}

// Replay evaluates every record with the same pipeline the live hook uses
// and summarizes the decisions. It writes no audit and executes nothing.
func Replay(engine *policy.Engine, records []ReplayRecord, opts Options, ropts ReplayOptions) (ReplayReport, error) {
	if engine == nil {
		return ReplayReport{}, errors.New("policy engine is required")
	}
	if ropts.Top <= 0 {
		ropts.Top = 25
	}
	allowed := map[string]bool{}
	tools := ropts.Tools
	if tools == nil {
		tools = strings.Split(DefaultMatcher, "|")
	}
	for _, t := range tools {
		allowed[t] = true
	}
	report := ReplayReport{
		Policy:      opts.BundleLabel,
		Permissions: map[string]int{},
		AskClasses:  map[string]int{},
		ByTool:      map[string]int{},
	}
	programs := map[string]int{}
	commands := map[string]int{}
	commandPermission := map[string]string{}
	for _, rec := range records {
		if !allowed[rec.ToolName] && !(ropts.IncludeMCP && strings.HasPrefix(rec.ToolName, "mcp__")) {
			report.Skipped++
			continue
		}
		in := Input{
			SessionID:      "replay",
			Cwd:            rec.Cwd,
			HookEventName:  hookEventName,
			PermissionMode: "replay",
			ToolName:       rec.ToolName,
			ToolInput:      rec.ToolInput,
			ToolUseID:      "replay",
		}
		if in.Cwd == "" {
			in.Cwd = opts.WorkspaceRoot
		}
		res, err := Evaluate(engine, in, opts)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", rec.Source, err))
			continue
		}
		report.Records++
		report.ByTool[rec.ToolName]++
		perm := res.Permission
		if perm == "" {
			perm = "passthrough"
		}
		report.Permissions[perm]++
		item := ReplayItem{Tool: rec.ToolName, Command: replayCommand(rec), Source: rec.Source, Permission: perm, Reason: res.Reason}
		switch perm {
		case PermissionDeny:
			report.Denies = append(report.Denies, item)
		case PermissionAsk:
			item.Class = askClass(res)
			report.AskClasses[item.Class]++
			programs[askProgram(res, rec)]++
			if ropts.KeepAsks {
				report.Asks = append(report.Asks, item)
			}
		}
		if rec.ToolName == "Bash" {
			commands[item.Command]++
			commandPermission[item.Command] = perm
		}
	}
	report.AskPrograms = topCounts(programs, ropts.Top)
	for cmd, n := range commands {
		report.TopCommands = append(report.TopCommands, ReplayCommand{Command: cmd, Count: n, Permission: commandPermission[cmd]})
	}
	sort.SliceStable(report.TopCommands, func(i, j int) bool {
		if report.TopCommands[i].Count != report.TopCommands[j].Count {
			return report.TopCommands[i].Count > report.TopCommands[j].Count
		}
		return report.TopCommands[i].Command < report.TopCommands[j].Command
	})
	if len(report.TopCommands) > ropts.Top {
		report.TopCommands = report.TopCommands[:ropts.Top]
	}
	return report, nil
}

func replayCommand(rec ReplayRecord) string {
	var params map[string]any
	if err := json.Unmarshal(rec.ToolInput, &params); err == nil {
		for _, key := range []string{"command", "file_path", "path", "url"} {
			if v, ok := params[key].(string); ok && v != "" {
				return v
			}
		}
	}
	return clip(string(rec.ToolInput), 200)
}

// askClass names the strongest reason a result asks, in the order the hook
// itself ranks them: refused syntax first, then paths outside the
// workspace, then rules that require approval, then no matching rule.
func askClass(res Result) string {
	for _, f := range res.Mapping.Findings {
		if f.Kind == FindingUnsupported || f.Kind == FindingNormalization {
			return AskUnsupportedShell
		}
	}
	for _, f := range res.Mapping.Findings {
		if f.Kind == FindingOutsideWorkspace {
			return AskOutsideWorkspace
		}
	}
	for _, o := range res.Outcomes {
		if o.Decision.Decision == policy.DecisionRequireApproval {
			return AskApprovalRequired
		}
	}
	return AskNoMatchingRule
}

// askProgram names the program whose call caused the ask: the first
// non-allowed simple command's argv[0], or the first token of the command
// when the parser refused it.
func askProgram(res Result, rec ReplayRecord) string {
	for _, o := range res.Outcomes {
		if o.Decision.Decision == policy.DecisionAllow {
			continue
		}
		if argv, ok := o.Action.Params["argv"].([]any); ok && len(argv) > 0 {
			if s, ok := argv[0].(string); ok {
				return s
			}
		}
	}
	if rec.ToolName != "Bash" {
		return rec.ToolName
	}
	fields := strings.Fields(replayCommand(rec))
	if len(fields) == 0 {
		return "(empty)"
	}
	return clip(fields[0], 40)
}

func topCounts(counts map[string]int, top int) []ReplayCount {
	out := make([]ReplayCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, ReplayCount{Program: k, Count: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Program < out[j].Program
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

// Text renders the report for a terminal.
func (r ReplayReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "replay of %d tool calls against %s", r.Records, r.Policy)
	if r.Skipped > 0 {
		fmt.Fprintf(&b, " (%d calls to other tools skipped)", r.Skipped)
	}
	b.WriteString("\n")
	for _, p := range []string{PermissionAllow, PermissionAsk, PermissionDeny, "passthrough"} {
		if n := r.Permissions[p]; n > 0 || p != "passthrough" {
			fmt.Fprintf(&b, "  %-12s %6d  %5.1f%%\n", p, n, pct(n, r.Records))
		}
	}
	if r.Permissions[PermissionAsk] > 0 {
		b.WriteString("why calls ask:\n")
		for _, c := range []string{AskUnsupportedShell, AskOutsideWorkspace, AskApprovalRequired, AskNoMatchingRule} {
			if n := r.AskClasses[c]; n > 0 {
				fmt.Fprintf(&b, "  %-20s %6d\n", c, n)
			}
		}
		b.WriteString("programs that ask most:\n")
		for _, p := range r.AskPrograms {
			fmt.Fprintf(&b, "  %6d  %s\n", p.Count, p.Program)
		}
	}
	if len(r.Denies) > 0 {
		b.WriteString("denied calls:\n")
		for _, d := range r.Denies {
			fmt.Fprintf(&b, "  %s: %s\n      %s\n", d.Tool, clip(d.Command, 120), clip(d.Reason, 160))
		}
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "%d lines could not be replayed (first: %s)\n", len(r.Errors), r.Errors[0])
	}
	return b.String()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}
