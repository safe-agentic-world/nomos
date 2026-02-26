package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/janus/internal/action"
	"github.com/safe-agentic-world/janus/internal/credentials"
	"github.com/safe-agentic-world/janus/internal/executor"
	"github.com/safe-agentic-world/janus/internal/identity"
	"github.com/safe-agentic-world/janus/internal/policy"
	"github.com/safe-agentic-world/janus/internal/redact"
)

func TestCredentialBrokerLeaseAndExecInjectionNoLeak(t *testing.T) {
	dir := t.TempDir()
	broker, err := credentials.NewBroker([]credentials.Secret{{ID: "gh_token", EnvKey: "API_TOKEN", Value: "super-secret-token", TTLSeconds: 60}}, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	bundle := policy.Bundle{Version: "v1", Hash: "h", Rules: []policy.Rule{
		{ID: "allow-checkout", ActionType: "secrets.checkout", Resource: "secret://vault/github", Decision: policy.DecisionAllow},
		{ID: "allow-exec", ActionType: "process.exec", Resource: "file://workspace/**", Decision: policy.DecisionAllow, Obligations: map[string]any{"sandbox_mode": "local", "exec_allowlist": []any{[]any{"cmd", "/c", "echo"}}}},
	}}
	svc := New(policy.NewEngine(bundle), executor.NewFSReader(dir, 64*1024, 200), executor.NewFSWriter(dir, 64*1024), executor.NewPatchApplier(dir, 64*1024), executor.NewExecRunner(dir, 64*1024), executor.NewHTTPRunner(64*1024), &recordSink{}, redact.DefaultRedactor(), nil, broker, "local", func() time.Time { return time.Unix(0, 0) })

	checkoutAct, err := action.ToAction(action.Request{SchemaVersion: "v1", ActionID: "a1", ActionType: "secrets.checkout", Resource: "secret://vault/github", Params: []byte(`{"secret_id":"gh_token"}`), TraceID: "t1", Context: action.Context{Extensions: map[string]json.RawMessage{}}}, identity.VerifiedIdentity{Principal: "p", Agent: "a", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action checkout: %v", err)
	}
	checkoutResp, err := svc.Process(checkoutAct)
	if err != nil {
		t.Fatalf("process checkout: %v", err)
	}
	if checkoutResp.CredentialLeaseID == "" {
		t.Fatal("expected lease id")
	}
	if strings.Contains(checkoutResp.Output, "super-secret-token") {
		t.Fatal("secret should never be returned")
	}

	execAct, err := action.ToAction(action.Request{SchemaVersion: "v1", ActionID: "a2", ActionType: "process.exec", Resource: "file://workspace/", Params: []byte(`{"argv":["cmd","/c","echo","%API_TOKEN%"],"cwd":"","env_allowlist_keys":["API_TOKEN"],"credential_lease_ids":["` + checkoutResp.CredentialLeaseID + `"]}`), TraceID: "t1", Context: action.Context{Extensions: map[string]json.RawMessage{}}}, identity.VerifiedIdentity{Principal: "p", Agent: "a", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action exec: %v", err)
	}
	execResp, err := svc.Process(execAct)
	if err != nil {
		t.Fatalf("process exec: %v", err)
	}
	if execResp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", execResp.Decision)
	}
	if strings.Contains(execResp.Stdout, "super-secret-token") {
		t.Fatalf("secret leaked in stdout: %s", execResp.Stdout)
	}
	if !strings.Contains(execResp.Stdout, "[REDACTED]") {
		t.Fatalf("expected redacted secret in stdout, got %s", execResp.Stdout)
	}
}
