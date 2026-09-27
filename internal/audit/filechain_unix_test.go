//go:build unix

package audit

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

// A FIFO planted at the audit path must fail the write at once: a blocked open
// would stall the hook until the harness timed it out and let the call through.
func TestFileChainRecorderRefusesFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	rec, err := NewFileChainRecorder(path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- rec.WriteEvent(Event{Timestamp: time.Now(), EventType: "hook.decision", TraceID: "s"})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a write to a FIFO audit path must fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteEvent blocked on a FIFO audit path")
	}
	verified := make(chan error, 1)
	go func() {
		_, err := VerifyFileChain(path)
		verified <- err
	}()
	select {
	case err := <-verified:
		if err == nil {
			t.Fatal("verifying a FIFO audit path must fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VerifyFileChain blocked on a FIFO audit path")
	}
}
