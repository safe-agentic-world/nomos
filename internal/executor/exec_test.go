package executor

import (
	"runtime"
	"strings"
	"testing"
)

func TestExecRunnerRejectsShellInterpreters(t *testing.T) {
	runner := NewExecRunner(t.TempDir(), 1024)
	argv := []string{"sh", "-c", "echo ok"}
	if runtime.GOOS == "windows" {
		argv = []string{"cmd.exe", "/c", "echo", "ok"}
	}
	_, err := runner.Run(ExecParams{Argv: argv})
	if err == nil {
		t.Fatal("expected shell interpreter rejection")
	}
	if !strings.Contains(err.Error(), "shell interpreter commands are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecRunnerLeavesFlagsToPolicyWhenArgvIsConstrained(t *testing.T) {
	runner := NewExecRunner(t.TempDir(), 1024)
	argv := []string{"echo", "--silent"}
	if runtime.GOOS == "windows" {
		t.Skip("echo is a cmd builtin on windows")
	}
	if _, err := runner.Run(ExecParams{Argv: argv}); err == nil || !strings.Contains(err.Error(), "must not start with --") {
		t.Fatalf("without policy-constrained argv the runner must refuse a -- flag, got %v", err)
	}
	result, err := runner.Run(ExecParams{Argv: argv, ArgvConstrainedByPolicy: true})
	if err != nil {
		t.Fatalf("policy-constrained argv must run: %v", err)
	}
	if !strings.Contains(result.Stdout, "--silent") {
		t.Fatalf("stdout = %q", result.Stdout)
	}
	// A bare "--" separator was always accepted.
	if _, err := runner.Run(ExecParams{Argv: []string{"echo", "--", "x"}}); err != nil {
		t.Fatalf("bare -- separator: %v", err)
	}
}
