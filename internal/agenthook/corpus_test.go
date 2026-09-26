package agenthook

import (
	"bufio"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/launcher"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

var updateCorpusGolden = flag.Bool("update-corpus", false, "rewrite testdata/realworld/expected.json from the current profiles")

// corpusSummary is what the golden file records per profile: how the
// real-world corpus decides, and every command that is denied, so a profile
// change that denies something new (or stops denying something) is reviewed.
type corpusSummary struct {
	Records     int            `json:"records"`
	Permissions map[string]int `json:"permissions"`
	AskClasses  map[string]int `json:"ask_classes"`
	Denies      []string       `json:"denies"`
}

func loadCorpus(t *testing.T) []ReplayRecord {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "realworld", "commands.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()
	var records []ReplayRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		recs, err := ParseReplayLine(scanner.Text(), "commands.jsonl")
		if err != nil {
			t.Fatalf("corpus line %d: %v", line, err)
		}
		records = append(records, recs...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if len(records) < 1000 {
		t.Fatalf("corpus unexpectedly small: %d records", len(records))
	}
	return records
}

func TestRealWorldCorpusDecisionsMatchGolden(t *testing.T) {
	records := loadCorpus(t)
	root := newWorkspace(t)
	goldenPath := filepath.Join("..", "..", "testdata", "realworld", "expected.json")
	got := map[string]corpusSummary{}
	for _, name := range launcher.EmbeddedProfileNames() {
		bundle, err := launcher.EmbeddedProfileBundle(name)
		if err != nil {
			t.Fatalf("profile %s: %v", name, err)
		}
		opts := Options{
			WorkspaceRoot:    root,
			Identity:         identity.VerifiedIdentity{Principal: "developer", Agent: "claude-code", Environment: "local"},
			OnDefaultDeny:    ModeAsk,
			OnUnsupported:    ModeAsk,
			OutsideWorkspace: ModeAsk,
			BundleLabel:      "profile " + name,
			HomeDir:          filepath.Join(filepath.Dir(root), "home"),
		}
		report, err := Replay(policy.NewEngine(bundle), records, opts, ReplayOptions{Top: 40})
		if err != nil {
			t.Fatalf("replay %s: %v", name, err)
		}
		if len(report.Errors) != 0 {
			t.Fatalf("replay %s reported errors: %v", name, report.Errors)
		}
		denies := make([]string, 0, len(report.Denies))
		for _, d := range report.Denies {
			denies = append(denies, d.Command)
		}
		sort.Strings(denies)
		got[name] = corpusSummary{Records: report.Records, Permissions: report.Permissions, AskClasses: report.AskClasses, Denies: denies}
		t.Logf("%s: %d records, allow %d, ask %d, deny %d; programs that ask most: %v", name, report.Records, report.Permissions[PermissionAllow], report.Permissions[PermissionAsk], report.Permissions[PermissionDeny], report.AskPrograms[:min(10, len(report.AskPrograms))])
	}
	if *updateCorpusGolden {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("encode golden: %v", err)
		}
		if err := os.WriteFile(goldenPath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s", goldenPath)
		return
	}
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update-corpus to create it): %v", err)
	}
	var want map[string]corpusSummary
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	for name, g := range got {
		w, ok := want[name]
		if !ok {
			t.Errorf("%s: missing from golden", name)
			continue
		}
		if !reflect.DeepEqual(g.Permissions, w.Permissions) || !reflect.DeepEqual(g.AskClasses, w.AskClasses) || g.Records != w.Records {
			t.Errorf("%s: decision counts changed: got %+v %+v, golden %+v %+v. Review the change and run: go test ./internal/agenthook -run Corpus -update-corpus", name, g.Permissions, g.AskClasses, w.Permissions, w.AskClasses)
		}
		if !reflect.DeepEqual(g.Denies, w.Denies) {
			t.Errorf("%s: the set of denied commands changed.\n  now denied but not in golden: %v\n  in golden but no longer denied: %v\nReview each command: a benign command must not be denied, an incident command must not be freed. Then run: go test ./internal/agenthook -run Corpus -update-corpus", name, diffStrings(g.Denies, w.Denies), diffStrings(w.Denies, g.Denies))
		}
	}
}

func diffStrings(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if !set[s] {
			out = append(out, s)
		}
	}
	return out
}
