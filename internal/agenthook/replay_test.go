package agenthook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReplayLineAcceptsFourShapes(t *testing.T) {
	recs, err := ParseReplayLine(`{"command":"go test ./...","cwd":"/w"}`, "corpus:1")
	if err != nil || len(recs) != 1 || recs[0].ToolName != "Bash" || recs[0].Cwd != "/w" || !strings.Contains(string(recs[0].ToolInput), "go test") {
		t.Fatalf("corpus line: %+v err=%v", recs, err)
	}
	recs, err = ParseReplayLine(`{"tool_name":"Read","tool_input":{"file_path":"a.go"}}`, "hook:1")
	if err != nil || len(recs) != 1 || recs[0].ToolName != "Read" {
		t.Fatalf("hook line: %+v err=%v", recs, err)
	}
	recs, err = ParseReplayLine(`{"type":"assistant","cwd":"/p","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}},{"type":"tool_use","name":"Edit","input":{"file_path":"x"}}]}}`, "transcript:1")
	if err != nil || len(recs) != 2 || recs[0].ToolName != "Bash" || recs[1].ToolName != "Edit" || recs[1].Cwd != "/p" {
		t.Fatalf("transcript line: %+v err=%v", recs, err)
	}
	recs, err = ParseReplayLine(`{"type":"user","message":{"role":"user","content":"hi"}}`, "transcript:2")
	if err != nil || len(recs) != 0 {
		t.Fatalf("user transcript line must yield nothing: %+v err=%v", recs, err)
	}
	recs, err = ParseReplayLine(`  rm -rf build/  `, "plain:1")
	if err != nil || len(recs) != 1 || !strings.Contains(string(recs[0].ToolInput), `rm -rf build/`) {
		t.Fatalf("plain line: %+v err=%v", recs, err)
	}
	for _, blank := range []string{"", "   ", "# comment"} {
		if recs, err := ParseReplayLine(blank, "x"); err != nil || len(recs) != 0 {
			t.Fatalf("blank %q: %+v err=%v", blank, recs, err)
		}
	}
	if _, err := ParseReplayLine(`{"unexpected":true}`, "bad:1"); err == nil {
		t.Fatalf("unrecognized object must error")
	}
	if _, err := ParseReplayLine(`{"tool_name":""}`, "bad:2"); err == nil {
		t.Fatalf("empty tool name must error")
	}
}

func TestReplaySummarizesDecisionsFromMixedFile(t *testing.T) {
	root := newWorkspace(t)
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Open(filepath.Join("testdata", "replay-mixed.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	records, errs := ReadReplayFile(f, "replay-mixed.jsonl")
	if len(errs) != 1 || !strings.Contains(errs[0], "unrecognized record shape") {
		t.Fatalf("expected exactly one unparseable line, got %v", errs)
	}
	if len(records) != 10 {
		t.Fatalf("expected 10 records, got %d", len(records))
	}
	report, err := Replay(testEngine(t), records, testOptions(t, root), ReplayOptions{KeepAsks: true})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if report.Skipped != 2 {
		t.Fatalf("mcp and TodoWrite calls must be skipped by default: %d", report.Skipped)
	}
	if report.Records != 8 {
		t.Fatalf("records: %d", report.Records)
	}
	// go test (no rule) asks, cat config/.env denies, Read allows, push asks
	// (approval), echo $HOME asks (unsupported), Write allows, ls asks (no rule),
	// cat ../secret.txt asks (outside).
	want := map[string]int{PermissionAllow: 2, PermissionAsk: 5, PermissionDeny: 1}
	for k, v := range want {
		if report.Permissions[k] != v {
			t.Fatalf("permission %s: got %d want %d (%+v)", k, report.Permissions[k], v, report.Permissions)
		}
	}
	if report.AskClasses[AskUnsupportedShell] != 1 || report.AskClasses[AskOutsideWorkspace] != 1 || report.AskClasses[AskApprovalRequired] != 1 || report.AskClasses[AskNoMatchingRule] != 2 {
		t.Fatalf("ask classes: %+v", report.AskClasses)
	}
	if len(report.Denies) != 1 || report.Denies[0].Command != "cat config/.env" || !strings.Contains(report.Denies[0].Reason, "deny-secret-file-args") {
		t.Fatalf("denies: %+v", report.Denies)
	}
	if len(report.Asks) != 5 {
		t.Fatalf("asks must be kept: %d", len(report.Asks))
	}
	programs := map[string]int{}
	for _, p := range report.AskPrograms {
		programs[p.Program] = p.Count
	}
	if programs["git"] != 1 || programs["go"] != 1 || programs["ls"] != 1 || programs["echo"] != 1 || programs["cat"] != 1 {
		t.Fatalf("ask programs: %+v", report.AskPrograms)
	}
	if report.ByTool["Bash"] != 6 || report.ByTool["Read"] != 1 || report.ByTool["Write"] != 1 {
		t.Fatalf("by tool: %+v", report.ByTool)
	}
	text := report.Text()
	for _, want := range []string{"replay of 8 tool calls", "2 calls to other tools skipped", "why calls ask", "denied calls", "cat config/.env"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text report missing %q:\n%s", want, text)
		}
	}
	mcp, err := Replay(testEngine(t), records, testOptions(t, root), ReplayOptions{IncludeMCP: true})
	if err != nil || mcp.Records != 9 || mcp.Skipped != 1 {
		t.Fatalf("mcp replay: records=%d skipped=%d err=%v", mcp.Records, mcp.Skipped, err)
	}
}

func TestReadTranscriptDirExtractsToolUses(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "-home-user-project")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	lines := `{"type":"assistant","cwd":"/home/user/project","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"go build ./..."}}]}}
{"type":"user","message":{"role":"user","content":"do it"}}
{"type":"assistant","cwd":"/home/user/project","message":{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"/home/user/project/main.go"}}]}}
`
	if err := os.WriteFile(filepath.Join(nested, "session.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "ignored.txt"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	records, errs, err := ReadTranscriptDir(dir)
	if err != nil || len(errs) != 0 {
		t.Fatalf("read: err=%v errs=%v", err, errs)
	}
	if len(records) != 2 || records[0].ToolName != "Bash" || records[1].ToolName != "Read" || records[0].Cwd != "/home/user/project" {
		t.Fatalf("records: %+v", records)
	}
	if _, _, err := ReadTranscriptDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatalf("missing dir must error")
	}
}
