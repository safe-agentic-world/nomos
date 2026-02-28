package service

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestM20SecretNeverLeaksFromExecOutputOrAudit(t *testing.T) {
	dir := t.TempDir()
	recorder := &recordSink{}
	secretValue := "super-secret-value-123"
	broker, err := credentials.NewBroker([]credentials.Secret{
		{ID: "github_token", EnvKey: "API_TOKEN", Value: secretValue, TTLSeconds: 60},
	}, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	argv, allowPrefix := secretEchoCommand()
	bundle := policy.Bundle{
		Version: "v1",
		Hash:    "bundle-hash-m20",
		Rules: []policy.Rule{
			{
				ID:           "allow-secret-checkout",
				ActionType:   "secrets.checkout",
				Resource:     "secret://vault/github_token",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "allow-exec-print",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"sandbox_mode":   "local",
					"exec_allowlist": []any{allowPrefix},
				},
			},
		},
	}
	svc := New(
		policy.NewEngine(bundle),
		executor.NewFSReader(dir, 64*1024, 200),
		executor.NewFSWriter(dir, 64*1024),
		executor.NewPatchApplier(dir, 64*1024),
		executor.NewExecRunner(dir, 64*1024),
		executor.NewHTTPRunner(64*1024),
		recorder,
		redact.DefaultRedactor(),
		nil,
		broker,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)

	checkoutResp, err := svc.Process(mustAction(t, action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-m20-checkout",
		ActionType:    "secrets.checkout",
		Resource:      "secret://vault/github_token",
		Params:        []byte(`{"secret_id":"github_token"}`),
		TraceID:       "trace-m20",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}))
	if err != nil {
		t.Fatalf("checkout process: %v", err)
	}
	if checkoutResp.CredentialLeaseID == "" {
		t.Fatal("expected credential lease id")
	}

	execParams, err := json.Marshal(map[string]any{
		"argv":                 argv,
		"cwd":                  "",
		"env_allowlist_keys":   []string{"API_TOKEN"},
		"credential_lease_ids": []string{checkoutResp.CredentialLeaseID},
	})
	if err != nil {
		t.Fatalf("marshal exec params: %v", err)
	}
	execResp, err := svc.Process(mustAction(t, action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-m20-exec",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        execParams,
		TraceID:       "trace-m20",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}))
	if err != nil {
		t.Fatalf("exec process: %v", err)
	}
	if strings.Contains(execResp.Stdout, secretValue) || strings.Contains(execResp.Stderr, secretValue) {
		t.Fatalf("secret leaked in exec response: stdout=%q stderr=%q", execResp.Stdout, execResp.Stderr)
	}
	if !strings.Contains(execResp.Stdout, "[REDACTED]") {
		t.Fatalf("expected redacted stdout, got %q", execResp.Stdout)
	}

	foundCompleted := false
	for _, event := range recorder.events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal audit event: %v", err)
		}
		if strings.Contains(string(data), secretValue) {
			t.Fatalf("secret leaked in audit event %s: %s", event.EventType, string(data))
		}
		if event.EventType == "action.completed" && event.ActionID == "act-m20-exec" {
			foundCompleted = true
			if len(event.CredentialLeaseIDs) != 1 || event.CredentialLeaseIDs[0] != checkoutResp.CredentialLeaseID {
				t.Fatalf("expected only lease refs in audit event, got %+v", event.CredentialLeaseIDs)
			}
		}
	}
	if !foundCompleted {
		t.Fatal("expected action.completed audit event for exec")
	}
}

func mustAction(t *testing.T, req action.Request) action.Action {
	t.Helper()
	act, err := action.ToAction(req, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

func secretEchoCommand() ([]string, []any) {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", "echo", "%API_TOKEN%"}, []any{"cmd", "/c", "echo"}
	}
	return []string{"sh", "-c", "printf %s \"$API_TOKEN\""}, []any{"sh", "-c", "printf %s \"$API_TOKEN\""}
}
