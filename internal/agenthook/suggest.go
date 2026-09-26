package agenthook

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
)

const (
	hookCompletedEventType = "hook.completed"
	postToolUseEvent       = "PostToolUse"
)

// CompletionEvent records that a tool call ran (Claude Code's PostToolUse
// hook fires only after the call completed, so the user approved any ask).
// Joined with the PreToolUse decision for the same tool_use_id, it tells
// which asks were answered yes, which is what `--suggest` learns from.
func CompletionEvent(in Input, opts Options, now time.Time) audit.Event {
	var params map[string]any
	_ = json.Unmarshal(in.ToolInput, &params)
	summary := in.ToolName
	if cmd, ok := params["command"].(string); ok && cmd != "" {
		summary += " " + truncate(cmd)
	} else if p := firstString(params, "file_path", "path", "url"); p != "" {
		summary += " " + p
	}
	return audit.Event{
		SchemaVersion: "v1",
		Timestamp:     now.UTC(),
		EventType:     hookCompletedEventType,
		TraceID:       sanitizeID(in.SessionID, "session"),
		ActionID:      sanitizeID(in.ToolUseID, "hook") + "-ran",
		Principal:     opts.Identity.Principal,
		Agent:         opts.Identity.Agent,
		Environment:   opts.Identity.Environment,
		ActionSummary: summary,
		ExecutorMetadata: map[string]any{
			"hook_event":      postToolUseEvent,
			"tool_name":       in.ToolName,
			"permission_mode": in.PermissionMode,
			"policy_label":    opts.BundleLabel,
		},
	}
}

// Suggestion is one allow rule a user could add, with the evidence for it.
type Suggestion struct {
	RuleID   string     `json:"rule_id"`
	Patterns [][]string `json:"argv_patterns"`
	// Approved counts the asked tool calls the user then ran that this rule
	// would have allowed.
	Approved int      `json:"approved"`
	Examples []string `json:"examples"`
}

// SuggestReport summarizes the audit log for rule suggestions.
type SuggestReport struct {
	Decisions     int          `json:"decisions"`
	Asked         int          `json:"asked"`
	AskedAndRan   int          `json:"asked_and_ran"`
	AskedNotRan   int          `json:"asked_not_ran"`
	NoCompletions bool         `json:"no_completion_records"`
	Suggestions   []Suggestion `json:"suggestions"`
}

// Suggest reads a hook audit log and proposes allow rules for the commands
// that asked for confirmation because no rule matched and that the user
// then approved. It never writes a policy: the output is a snippet for a
// human to review and commit. Commands that asked for any other reason
// (refused syntax, a path outside the workspace, a rule that requires
// approval) are never suggested, and neither is anything the user did not
// run.
func Suggest(r io.Reader, top int) (SuggestReport, error) {
	if top <= 0 {
		top = 20
	}
	type askedCall struct {
		argvs [][]string
	}
	asked := map[string]*askedCall{}
	ran := map[string]bool{}
	var report SuggestReport
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxInputBytes)
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		base := strings.TrimSuffix(ev.ActionID, "-ran")
		if i := strings.LastIndex(base, "-"); i > 0 && ev.EventType == hookEventType {
			base = base[:i]
		}
		switch ev.EventType {
		case hookCompletedEventType:
			ran[base] = true
		case hookEventType:
			report.Decisions++
			perm, _ := ev.ExecutorMetadata["hook_permission"].(string)
			if perm != PermissionAsk {
				continue
			}
			call := asked[base]
			if call == nil {
				call = &askedCall{}
				asked[base] = call
				report.Asked++
			}
			if ev.ActionType == "process.exec" && ev.Reason == "deny_by_default" {
				if argv := stringSlice(ev.ExecutorMetadata["argv"]); len(argv) > 0 {
					call.argvs = append(call.argvs, argv)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return report, err
	}
	report.NoCompletions = len(ran) == 0
	counts := map[string]*Suggestion{}
	for base, call := range asked {
		if !ran[base] {
			report.AskedNotRan++
			continue
		}
		report.AskedAndRan++
		for _, argv := range call.argvs {
			key, patterns := suggestionFor(argv)
			s := counts[key]
			if s == nil {
				s = &Suggestion{RuleID: "allow-" + strings.ReplaceAll(strings.ReplaceAll(key, " ", "-"), "/", "-"), Patterns: patterns}
				counts[key] = s
			}
			s.Approved++
			if len(s.Examples) < 3 {
				s.Examples = append(s.Examples, strings.Join(argv, " "))
			}
		}
	}
	for _, s := range counts {
		report.Suggestions = append(report.Suggestions, *s)
	}
	sort.SliceStable(report.Suggestions, func(i, j int) bool {
		if report.Suggestions[i].Approved != report.Suggestions[j].Approved {
			return report.Suggestions[i].Approved > report.Suggestions[j].Approved
		}
		return report.Suggestions[i].RuleID < report.Suggestions[j].RuleID
	})
	if len(report.Suggestions) > top {
		report.Suggestions = report.Suggestions[:top]
	}
	return report, nil
}

// suggestionFor picks the narrowest useful pattern for an approved command:
// the program plus its subcommand when the second token looks like one
// (`git fetch`, `cargo build`), else the program alone.
func suggestionFor(argv []string) (string, [][]string) {
	prog := argv[0]
	if len(argv) > 1 {
		sub := argv[1]
		if sub != "" && !strings.HasPrefix(sub, "-") && !strings.ContainsAny(sub, "/.\\=~*?$") {
			return prog + " " + sub, [][]string{{prog, sub}, {prog, sub, "**"}}
		}
	}
	return prog, [][]string{{prog}, {prog, "**"}}
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// Text renders the report with a YAML snippet ready to paste into a bundle.
func (r SuggestReport) Text(label string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d hook decisions, %d asked for confirmation", r.Decisions, r.Asked)
	if r.NoCompletions {
		b.WriteString("\nno completion records found: install the PostToolUse hook (nomos hook claude-code --install) so approved calls are recorded, then run again\n")
		return b.String()
	}
	fmt.Fprintf(&b, ": %d were approved and ran, %d were not run\n", r.AskedAndRan, r.AskedNotRan)
	if len(r.Suggestions) == 0 {
		b.WriteString("no approved calls were asked because a rule was missing; nothing to suggest\n")
		return b.String()
	}
	b.WriteString("allow rules that would have removed those prompts (review, then add to your bundle):\n")
	for _, s := range r.Suggestions {
		fmt.Fprintf(&b, "  %4d  %-24s e.g. %s\n", s.Approved, s.RuleID, strings.Join(s.Examples, " | "))
	}
	b.WriteString("\nrules:\n")
	for _, s := range r.Suggestions {
		fmt.Fprintf(&b, "  - id: %s\n    action_type: process.exec\n    resource: file://workspace/\n    decision: ALLOW\n    exec_match:\n      argv_patterns:\n", s.RuleID)
		for _, p := range s.Patterns {
			quoted := make([]string, len(p))
			for i, tok := range p {
				quoted[i] = fmt.Sprintf("%q", tok)
			}
			fmt.Fprintf(&b, "        - [%s]\n", strings.Join(quoted, ", "))
		}
	}
	if label != "" {
		fmt.Fprintf(&b, "\nSuggestions are derived from %s decisions; nothing was written.\n", label)
	}
	return b.String()
}

// ReadAuditFile opens a hook audit log for Suggest.
func ReadAuditFile(path string) (*os.File, error) {
	return os.Open(path)
}
