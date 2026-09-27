package main

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureWatchdog replaces the watchdog's exit with a recorder for one test.
func captureWatchdog(t *testing.T) <-chan int {
	t.Helper()
	codes := make(chan int, 1)
	previous := hookWatchdogExit
	hookWatchdogExit = func(code int) { codes <- code }
	t.Cleanup(func() { hookWatchdogExit = previous })
	return codes
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHookWatchdogBlocksAfterDeadline(t *testing.T) {
	codes := captureWatchdog(t)
	var stderr syncBuffer
	stop := startHookWatchdog(50*time.Millisecond, &stderr)
	defer stop()
	select {
	case code := <-codes:
		if code != hookExitError {
			t.Fatalf("watchdog exit code = %d, want %d", code, hookExitError)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not fire")
	}
	if !strings.Contains(stderr.String(), "blocking the tool call") {
		t.Fatalf("watchdog must explain the block on stderr, got %q", stderr.String())
	}
}

func TestHookWatchdogDisarmsOnReturn(t *testing.T) {
	codes := captureWatchdog(t)
	stop := startHookWatchdog(50*time.Millisecond, io.Discard)
	stop()
	select {
	case code := <-codes:
		t.Fatalf("a disarmed watchdog fired with %d", code)
	case <-time.After(200 * time.Millisecond):
	}
	startHookWatchdog(0, io.Discard)() // zero disables it
}

func TestHookDeadlineFitsTheTimeout(t *testing.T) {
	if defaultHookDeadline != 8*time.Second {
		t.Fatalf("default deadline = %s, want 8s inside the 10s default timeout", defaultHookDeadline)
	}
	for timeout, want := range map[int]string{10: "", 30: " --deadline 28s", 3: " --deadline 1.5s", 1: " --deadline 500ms"} {
		if got := deadlineFlag(timeout); got != want {
			t.Errorf("deadlineFlag(%d) = %q, want %q", timeout, got, want)
		}
	}
}

// A decision that cannot finish (here, hook input that never arrives) must
// become a block before the harness timeout, not a silent timeout.
func TestClaudeCodeHookWatchdogBlocksAStalledDecision(t *testing.T) {
	codes := captureWatchdog(t)
	stdin, writer := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- runClaudeCodeHook([]string{"--profile", "safe-dev", "--workspace", t.TempDir(), "--audit", "none", "--deadline", "100ms"}, stdin, &stdout, &stderr, noEnv)
	}()
	select {
	case code := <-codes:
		if code != hookExitError {
			t.Fatalf("watchdog exit code = %d, want %d", code, hookExitError)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watchdog did not block a stalled decision")
	}
	_ = writer.Close()
	<-done
	if !strings.Contains(stderr.String(), "no decision within 100ms") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCodexHookWatchdogBlocksAStalledDecision(t *testing.T) {
	codes := captureWatchdog(t)
	stdin, writer := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- runCodexHook([]string{"--profile", "safe-dev", "--workspace", t.TempDir(), "--audit", "none", "--deadline", "100ms"}, stdin, &stdout, &stderr, noEnv)
	}()
	select {
	case code := <-codes:
		if code != hookExitError {
			t.Fatalf("watchdog exit code = %d, want %d", code, hookExitError)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watchdog did not block a stalled Codex decision")
	}
	_ = writer.Close()
	<-done
}

func TestInstallersAddADeadlineForACustomTimeout(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runClaudeCodeHook([]string{"--print-settings", "--timeout", "30"}, strings.NewReader(""), &out, &errOut, noEnv); code != hookExitOK {
		t.Fatalf("print-settings exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "--deadline 28s") {
		t.Fatalf("a 30s timeout must register --deadline 28s:\n%s", out.String())
	}
	out.Reset()
	if code := runClaudeCodeHook([]string{"--print-settings"}, strings.NewReader(""), &out, &errOut, noEnv); code != hookExitOK {
		t.Fatalf("print-settings exit %d: %s", code, errOut.String())
	}
	if strings.Contains(out.String(), "--deadline") {
		t.Fatalf("the default timeout needs no --deadline:\n%s", out.String())
	}
	out.Reset()
	if code := runCodexHook([]string{"--print-hooks", "--timeout", "30"}, strings.NewReader(""), &out, &errOut, noEnv); code != hookExitOK {
		t.Fatalf("print-hooks exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "--deadline 28s") {
		t.Fatalf("a 30s Codex timeout must register --deadline 28s:\n%s", out.String())
	}
}
