package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestSafetyVisibilityFields(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:         "allow-net",
				ActionType: "net.http_request",
				Resource:   "url://example.com/**",
				Decision:   policy.DecisionAllow,
				Obligations: map[string]any{
					"sandbox_mode":         "local",
					"net_allowlist":        []any{"example.com"},
					"credential_lease_ids": []any{"lease_1", "lease_2"},
				},
			},
		},
		Hash: "bundle-hash-visibility",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 64*1024, 200)
	writer := executor.NewFSWriter(dir, 64*1024)
	patcher := executor.NewPatchApplier(dir, 64*1024)
	execRunner := executor.NewExecRunner(dir, 64*1024)
	httpRunner := executor.NewHTTPRunner(64 * 1024)
	httpRunner.SetClient(newTestHTTPClient("ok"))
	recorder := &recordSink{}
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time {
		now = now.Add(10 * time.Millisecond)
		return now
	})
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-visibility-1",
		ActionType:    "net.http_request",
		Resource:      "url://example.com/path",
		Params:        []byte(`{"method":"GET"}`),
		TraceID:       "trace-visibility-1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	_, err = svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}

	found := false
	for _, e := range recorder.events {
		if e.EventType != "action.completed" {
			continue
		}
		found = true
		if e.RiskLevel == "" {
			t.Fatal("expected risk_level")
		}
		if e.PolicyBundleHash != "bundle-hash-visibility" {
			t.Fatalf("expected policy bundle hash, got %s", e.PolicyBundleHash)
		}
		if e.EngineVersion == "" {
			t.Fatal("expected engine_version")
		}
		if e.SandboxMode != "local" {
			t.Fatalf("expected sandbox_mode local, got %s", e.SandboxMode)
		}
		if e.NetworkMode != "allowlist" {
			t.Fatalf("expected network_mode allowlist, got %s", e.NetworkMode)
		}
		if len(e.CredentialLeaseIDs) != 2 || e.CredentialLeaseIDs[0] != "lease_1" {
			t.Fatalf("expected credential lease IDs only, got %+v", e.CredentialLeaseIDs)
		}
		if e.ActionSummary != "net.http_request url://example.com/path" {
			t.Fatalf("unexpected action summary: %s", e.ActionSummary)
		}
		if e.Decision == "" {
			t.Fatal("expected decision")
		}
	}
	if !found {
		t.Fatal("expected action.completed event")
	}
}
