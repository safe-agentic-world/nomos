package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/janus/internal/action"
	"github.com/safe-agentic-world/janus/internal/executor"
	"github.com/safe-agentic-world/janus/internal/identity"
	"github.com/safe-agentic-world/janus/internal/policy"
	"github.com/safe-agentic-world/janus/internal/redact"
)

func TestM8CompletedAuditEventFields(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow, Obligations: map[string]any{"net_allowlist": []any{"example.com"}}},
		},
		Hash: "bundlehash123",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 64*1024, 200)
	writer := executor.NewFSWriter(dir, 64*1024)
	patcher := executor.NewPatchApplier(dir, 64*1024)
	execRunner := executor.NewExecRunner(dir, 64*1024)
	httpRunner := executor.NewHTTPRunner(64 * 1024)
	recorder := &recordSink{}
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time {
		now = now.Add(10 * time.Millisecond)
		return now
	})

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-m8-1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{"note":"Authorization: secret-token"}`),
		TraceID:       "trace-m8-1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "janus", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	_, _ = svc.Process(act)

	var completedFound bool
	for _, e := range recorder.events {
		if e.EventType != "action.completed" {
			continue
		}
		completedFound = true
		if e.SchemaVersion != "v1" {
			t.Fatalf("expected schema version v1, got %s", e.SchemaVersion)
		}
		if e.TraceID == "" || e.ActionID == "" || e.Principal == "" || e.Agent == "" || e.Environment == "" {
			t.Fatalf("missing identity/trace fields: %+v", e)
		}
		if e.ActionType == "" || e.ResourceNormalized == "" || e.ParamsHash == "" {
			t.Fatalf("missing normalized action fields: %+v", e)
		}
		if e.Decision == "" || e.ResultClassification == "" {
			t.Fatalf("missing decision/classification fields: %+v", e)
		}
		if len(e.MatchedRuleIDs) == 0 {
			t.Fatalf("expected matched rules in completed event: %+v", e)
		}
		if e.PolicyBundleHash != "bundlehash123" {
			t.Fatalf("expected policy bundle hash, got %s", e.PolicyBundleHash)
		}
		if e.EngineVersion == "" {
			t.Fatal("expected engine version")
		}
		if e.DurationMS <= 0 {
			t.Fatalf("expected positive duration, got %d", e.DurationMS)
		}
		if strings.Contains(e.ParamsRedactedSummary, "secret-token") {
			t.Fatalf("expected params summary redacted, got %s", e.ParamsRedactedSummary)
		}
	}
	if !completedFound {
		t.Fatal("expected action.completed event")
	}
}
