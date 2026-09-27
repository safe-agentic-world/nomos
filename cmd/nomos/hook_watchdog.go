package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/safe-agentic-world/nomos/internal/agenthook"
)

// Claude Code and Codex let a tool call through when its hook times out, so a
// hook that stalls anywhere (a hung filesystem, a pipe planted where it reads
// its policy) grants the call. The watchdog turns any stall into a block: if
// no decision is written by the deadline, it reports on stderr and exits 2,
// which both harnesses treat as a block.
var defaultHookDeadline = hookDeadlineFor(agenthook.DefaultTimeoutSeconds)

// hookWatchdogExit is replaced in tests.
var hookWatchdogExit = os.Exit

// hookDeadlineFor leaves the hook two seconds of the harness timeout, or half
// of a timeout too short for that.
func hookDeadlineFor(timeoutSeconds int) time.Duration {
	timeout := time.Duration(timeoutSeconds) * time.Second
	deadline := timeout - 2*time.Second
	if deadline < timeout/2 {
		deadline = timeout / 2
	}
	return deadline
}

// deadlineFlag renders the --deadline argument an installer adds for a
// non-default timeout, or "" when the default deadline already fits.
func deadlineFlag(timeoutSeconds int) string {
	deadline := hookDeadlineFor(timeoutSeconds)
	if deadline == defaultHookDeadline || deadline <= 0 {
		return ""
	}
	return " --deadline " + shellQuote(deadline.String())
}

// startHookWatchdog arms the watchdog and returns the function that disarms
// it. A deadline of zero or less disables it.
func startHookWatchdog(deadline time.Duration, stderr io.Writer) func() {
	if deadline <= 0 {
		return func() {}
	}
	timer := time.AfterFunc(deadline, func() {
		fmt.Fprintf(stderr, "hook: no decision within %s; blocking the tool call\n", deadline)
		hookWatchdogExit(hookExitError)
	})
	return func() { timer.Stop() }
}
