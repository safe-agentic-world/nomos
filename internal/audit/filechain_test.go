package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestFileChainRecorderChainsAcrossInstancesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "hook-audit.jsonl")
	redactor := redact.DefaultRedactor()

	for i := 0; i < 3; i++ {
		rec, err := NewFileChainRecorder(path, redactor)
		if err != nil {
			t.Fatalf("new recorder: %v", err)
		}
		if err := rec.WriteEvent(Event{
			Timestamp:  time.Date(2026, 9, 25, 12, 0, i, 0, time.UTC),
			EventType:  "hook.decision",
			TraceID:    "session-1",
			ActionID:   "tool-" + string(rune('a'+i)),
			ActionType: "process.exec",
			Decision:   "DENY",
		}); err != nil {
			t.Fatalf("write event %d: %v", i, err)
		}
	}

	count, err := VerifyFileChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 verified events, got %d", count)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	var first, second Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if first.PrevEventHash != "" || first.EventHash == "" {
		t.Fatalf("first event chain fields wrong: %+v", first)
	}
	if second.PrevEventHash != first.EventHash {
		t.Fatalf("second event must link to first: prev=%q first=%q", second.PrevEventHash, first.EventHash)
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock file must be released, stat err=%v", err)
	}
}

func TestFileChainRecorderRedactsBeforeHashingAndDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rec, err := NewFileChainRecorder(path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	if err := rec.WriteEvent(Event{
		Timestamp:             time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
		EventType:             "hook.decision",
		TraceID:               "session-1",
		ActionID:              "tool-1",
		ResultRedactedSummary: "curl -H 'Authorization: Bearer abcdefghijklmnop'",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "abcdefghijklmnop") {
		t.Fatalf("stored line must be redacted: %s", data)
	}
	if !strings.Contains(string(data), "[REDACTED]") {
		t.Fatalf("expected redaction marker in stored line: %s", data)
	}
	if _, err := VerifyFileChain(path); err != nil {
		t.Fatalf("redacted line must verify: %v", err)
	}

	tampered := strings.Replace(string(data), `"tool-1"`, `"tool-9"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := VerifyFileChain(path); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestFileChainRecorderRejectsEmptyPath(t *testing.T) {
	if _, err := NewFileChainRecorder("  ", redact.DefaultRedactor()); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := NewFileChainRecorder(filepath.Join(t.TempDir(), "x.jsonl"), nil); err == nil {
		t.Fatal("expected error for nil redactor")
	}
}

func TestFileChainRecorderWaitsForStaleLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lock := path + ".lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	old := time.Now().Add(-2 * fileChainLockStale)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	rec, err := NewFileChainRecorder(path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	if err := rec.WriteEvent(Event{Timestamp: time.Now(), EventType: "hook.decision", TraceID: "s"}); err != nil {
		t.Fatalf("stale lock must be reclaimed: %v", err)
	}
}
