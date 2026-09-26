package agenthook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestSuggestProposesRulesOnlyForApprovedUnmatchedCommands(t *testing.T) {
	root := newWorkspace(t)
	engine := testEngine(t)
	opts := testOptions(t, root)
	var log bytes.Buffer
	now := time.Date(2026, 9, 26, 6, 0, 0, 0, time.UTC)
	write := func(events ...audit.Event) {
		for _, ev := range events {
			data, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			log.Write(redact.DefaultRedactor().RedactBytes(data))
			log.WriteByte('\n')
		}
	}
	call := func(id, command string) Input {
		in := toolInput(root, "Bash", map[string]any{"command": command})
		in.ToolUseID = id
		return in
	}
	decide := func(in Input) {
		res, err := Evaluate(engine, in, opts)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		write(AuditEvents(in, res, opts, now)...)
	}
	// make: asked (no rule), then ran twice.
	for _, id := range []string{"toolu_1", "toolu_2"} {
		in := call(id, "make test")
		decide(in)
		write(CompletionEvent(in, opts, now))
	}
	// cargo build: asked, ran once.
	in := call("toolu_3", "cargo build --release")
	decide(in)
	write(CompletionEvent(in, opts, now))
	// git push: asked because a rule requires approval; ran, but never suggested.
	in = call("toolu_4", "git push origin main")
	decide(in)
	write(CompletionEvent(in, opts, now))
	// ls: asked, not run (the user declined).
	decide(call("toolu_5", "ls -la"))
	// git status: allowed, ran.
	in = call("toolu_6", "git status")
	decide(in)
	write(CompletionEvent(in, opts, now))
	// a chain with an unmatched part and a variable: approved.
	in = call("toolu_7", "make lint && rm -rf $TMP")
	decide(in)
	write(CompletionEvent(in, opts, now))

	report, err := Suggest(bytes.NewReader(log.Bytes()), 10)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if report.NoCompletions {
		t.Fatalf("completion records were written")
	}
	if report.Asked != 6 || report.AskedAndRan != 5 || report.AskedNotRan != 1 {
		t.Fatalf("counts: %+v", report)
	}
	// make test (2), cargo build (1), and make lint (1, from the chain whose
	// other part was refused); never git push, ls, or rm.
	if len(report.Suggestions) != 3 {
		t.Fatalf("suggestions: %+v", report.Suggestions)
	}
	if report.Suggestions[0].RuleID != "allow-make-test" || report.Suggestions[0].Approved != 2 {
		t.Fatalf("first suggestion: %+v", report.Suggestions[0])
	}
	if report.Suggestions[1].RuleID != "allow-cargo-build" || report.Suggestions[1].Approved != 1 {
		t.Fatalf("second suggestion: %+v", report.Suggestions[1])
	}
	for _, s := range report.Suggestions {
		if strings.Contains(s.RuleID, "git") || strings.Contains(s.RuleID, "ls") || strings.Contains(s.RuleID, "rm") {
			t.Fatalf("approval-gated, declined, and refused commands must never be suggested: %+v", s)
		}
	}
	text := report.Text("test.jsonl")
	for _, want := range []string{"allow-make-test", `["make", "test", "**"]`, "nothing was written", "5 were approved and ran, 1 were not run"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text missing %q:\n%s", want, text)
		}
	}

	// Without completion records nothing is suggested.
	var decisionsOnly bytes.Buffer
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		if !strings.Contains(line, `"hook.completed"`) {
			decisionsOnly.WriteString(line + "\n")
		}
	}
	report, err = Suggest(&decisionsOnly, 10)
	if err != nil || !report.NoCompletions || len(report.Suggestions) != 0 {
		t.Fatalf("decisions only: %+v err=%v", report, err)
	}
	if !strings.Contains(report.Text(""), "no completion records") {
		t.Fatalf("text must explain the missing PostToolUse hook")
	}
}

func TestSuggestionForPicksSubcommandPatterns(t *testing.T) {
	key, patterns := suggestionFor([]string{"cargo", "build", "--release"})
	if key != "cargo build" || len(patterns) != 2 || strings.Join(patterns[1], " ") != "cargo build **" {
		t.Fatalf("cargo: %s %v", key, patterns)
	}
	key, patterns = suggestionFor([]string{"make", "-j4"})
	if key != "make" || strings.Join(patterns[1], " ") != "make **" {
		t.Fatalf("make: %s %v", key, patterns)
	}
	key, _ = suggestionFor([]string{"python", "script.py"})
	if key != "python" {
		t.Fatalf("path-like second token must not become a subcommand: %s", key)
	}
}
