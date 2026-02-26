package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safe-agentic-world/janus/internal/action"
	"github.com/safe-agentic-world/janus/internal/approval"
	"github.com/safe-agentic-world/janus/internal/audit"
	"github.com/safe-agentic-world/janus/internal/executor"
	"github.com/safe-agentic-world/janus/internal/identity"
	"github.com/safe-agentic-world/janus/internal/policy"
	"github.com/safe-agentic-world/janus/internal/redact"
)

func TestRequireApprovalBlocksAndResumeWithSameInput(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approvals.db"), 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open approval store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc, recorder := newApprovalServiceForTest(t, dir, store, nowFn)

	first := mustActionForApprovalTest(t, "act-apr-1", "trace-apr-1", "file://workspace/out.txt", `{"content":"one"}`, "")
	resp, err := svc.Process(first)
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	if resp.Decision != policy.DecisionRequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", resp.Decision)
	}
	if resp.ApprovalID == "" {
		t.Fatal("expected approval_id in response")
	}
	if _, err := os.Stat(filepath.Join(dir, "out.txt")); err == nil {
		t.Fatal("expected write not executed before approval")
	}

	if _, err := store.Decide(context.Background(), resp.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve decision: %v", err)
	}

	second := mustActionForApprovalTest(t, "act-apr-1", "trace-apr-1", "file://workspace/out.txt", `{"content":"one"}`, resp.ApprovalID)
	resp2, err := svc.Process(second)
	if err != nil {
		t.Fatalf("second process: %v", err)
	}
	if resp2.Decision != policy.DecisionAllow {
		t.Fatalf("expected ALLOW after approval, got %s", resp2.Decision)
	}
	if resp2.Reason != "allow_by_approval" {
		t.Fatalf("expected allow_by_approval reason, got %s", resp2.Reason)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(payload) != "one" {
		t.Fatalf("unexpected file content: %q", string(payload))
	}

	foundLinked := false
	for _, ev := range recorder.events {
		if ev.EventType == "approval.requested" {
			if ev.ApprovalID == "" || ev.TraceID != "trace-apr-1" || ev.ActionID != "act-apr-1" {
				t.Fatalf("invalid approval linkage event: %+v", ev)
			}
			foundLinked = true
		}
	}
	if !foundLinked {
		t.Fatal("expected approval.requested audit event")
	}
}

func TestApprovalDoesNotApplyWhenNormalizedInputChanges(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approvals.db"), 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open approval store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc, _ := newApprovalServiceForTest(t, dir, store, nowFn)

	first := mustActionForApprovalTest(t, "act-apr-2", "trace-apr-2", "file://workspace/out2.txt", `{"content":"one"}`, "")
	resp, err := svc.Process(first)
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	if resp.ApprovalID == "" {
		t.Fatal("expected approval id")
	}
	if _, err := store.Decide(context.Background(), resp.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve decision: %v", err)
	}

	changed := mustActionForApprovalTest(t, "act-apr-2", "trace-apr-2", "file://workspace/out2.txt", `{"content":"two"}`, resp.ApprovalID)
	resp2, err := svc.Process(changed)
	if err != nil {
		t.Fatalf("changed process: %v", err)
	}
	if resp2.Decision != policy.DecisionRequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL for changed input, got %s", resp2.Decision)
	}
	if resp2.ApprovalID == "" || resp2.ApprovalID == resp.ApprovalID {
		t.Fatal("expected a new approval id for changed normalized input")
	}
}

func newApprovalServiceForTest(t *testing.T, dir string, store *approval.Store, nowFn func() time.Time) (*Service, *recordSink) {
	t.Helper()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:         "require-approval-write",
				ActionType: "fs.write",
				Resource:   "file://workspace/**",
				Decision:   policy.DecisionRequireApproval,
			},
		},
		Hash: "bundle",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 64*1024, 100)
	writer := executor.NewFSWriter(dir, 64*1024)
	patcher := executor.NewPatchApplier(dir, 64*1024)
	execRunner := executor.NewExecRunner(dir, 64*1024)
	httpRunner := executor.NewHTTPRunner(64 * 1024)
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), store, nil, "local", nowFn)
	return svc, recorder
}

func mustActionForApprovalTest(t *testing.T, actionID, traceID, resource, params, approvalID string) action.Action {
	t.Helper()
	ext := map[string]json.RawMessage{}
	if approvalID != "" {
		ext["approval"] = json.RawMessage(`{"approval_id":"` + approvalID + `"}`)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      actionID,
		ActionType:    "fs.write",
		Resource:      resource,
		Params:        []byte(params),
		TraceID:       traceID,
		Context:       action.Context{Extensions: ext},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "janus", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

var _ audit.Recorder = (*recordSink)(nil)
