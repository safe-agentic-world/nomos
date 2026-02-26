package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/janus/internal/action"
	"github.com/safe-agentic-world/janus/internal/audit"
	"github.com/safe-agentic-world/janus/internal/identity"
)

func TestApprovalDecisionEndpointIdempotentAndStrict(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC) }
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"r1","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL"}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordSink{}
	gw, err := NewWithRecorder(Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Policy:  PolicyConfig{BundlePath: bundlePath},
		Executor: ExecutorConfig{
			WorkspaceRoot:  dir,
			MaxOutputBytes: 64 * 1024,
			MaxOutputLines: 200,
			SandboxProfile: "local",
		},
		Audit: AuditConfig{Sink: "stdout"},
		Approvals: ApprovalsConfig{
			Enabled:    true,
			StorePath:  filepath.Join(dir, "approvals.db"),
			TTLSeconds: 600,
		},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "janus",
			Environment: "dev",
			APIKeys:     map[string]string{"k": "system"},
			AgentSecrets: map[string]string{
				"janus": "agent-secret",
			},
		},
	}, recorder, now)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Shutdown(context.Background()) })

	approvalID := createPendingApproval(t, gw)

	payload := `{"approval_id":"` + approvalID + `","decision":"APPROVE"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/approvals/decide", strings.NewReader(payload))
	gw.handleApprovalDecision(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/approvals/decide", strings.NewReader(payload))
	gw.handleApprovalDecision(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected idempotent 200, got %d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/approvals/decide", strings.NewReader(`{"approval_id":"`+approvalID+`","decision":"DENY"}`))
	gw.handleApprovalDecision(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for conflicting decision, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/approvals/decide", strings.NewReader(`{"approval_id":"`+approvalID+`","decision":"APPROVE","extra":1}`))
	gw.handleApprovalDecision(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", w.Code)
	}
}

func TestApprovalWebhookToken(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC) }
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"r1","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL"}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordSink{}
	gw, err := NewWithRecorder(Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Policy:  PolicyConfig{BundlePath: bundlePath},
		Executor: ExecutorConfig{
			WorkspaceRoot:  dir,
			MaxOutputBytes: 64 * 1024,
			MaxOutputLines: 200,
			SandboxProfile: "local",
		},
		Audit: AuditConfig{Sink: "stdout"},
		Approvals: ApprovalsConfig{
			Enabled:      true,
			StorePath:    filepath.Join(dir, "approvals.db"),
			TTLSeconds:   600,
			WebhookToken: "token-1",
		},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "janus",
			Environment: "dev",
			APIKeys:     map[string]string{"k": "system"},
			AgentSecrets: map[string]string{
				"janus": "agent-secret",
			},
		},
	}, recorder, now)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Shutdown(context.Background()) })
	approvalID := createPendingApproval(t, gw)
	payload := `{"approval_id":"` + approvalID + `","decision":"APPROVE"}`

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/approvals", strings.NewReader(payload))
	gw.handleApprovalDecisionWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/webhooks/approvals", strings.NewReader(payload))
	req.Header.Set("X-Janus-Webhook-Token", "token-1")
	gw.handleApprovalDecisionWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSlackApprovalWebhook(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC) }
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"r1","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL"}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordSink{}
	gw, err := NewWithRecorder(Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Policy:  PolicyConfig{BundlePath: bundlePath},
		Executor: ExecutorConfig{
			WorkspaceRoot:  dir,
			MaxOutputBytes: 64 * 1024,
			MaxOutputLines: 200,
			SandboxProfile: "local",
		},
		Audit: AuditConfig{Sink: "stdout"},
		Approvals: ApprovalsConfig{
			Enabled:    true,
			StorePath:  filepath.Join(dir, "approvals.db"),
			TTLSeconds: 600,
			SlackToken: "slack-token-1",
		},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "janus",
			Environment: "dev",
			APIKeys:     map[string]string{"k": "system"},
			AgentSecrets: map[string]string{
				"janus": "agent-secret",
			},
		},
	}, recorder, now)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Shutdown(context.Background()) })
	approvalID := createPendingApproval(t, gw)

	w := httptest.NewRecorder()
	payload := `{"approval_id":"` + approvalID + `","decision":"APPROVE","user_id":"U1","channel_id":"C1"}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/slack/approvals", strings.NewReader(payload))
	gw.handleSlackApprovalWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/webhooks/slack/approvals", strings.NewReader(payload))
	req.Header.Set("X-Janus-Slack-Token", "slack-token-1")
	gw.handleSlackApprovalWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	found := false
	for _, event := range recorder.events {
		if event.EventType == "approval.decided.slack" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected approval.decided.slack audit event")
	}
}

func TestTeamsApprovalWebhookStrictSchema(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC) }
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"r1","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL"}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordSink{}
	gw, err := NewWithRecorder(Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Policy:  PolicyConfig{BundlePath: bundlePath},
		Executor: ExecutorConfig{
			WorkspaceRoot:  dir,
			MaxOutputBytes: 64 * 1024,
			MaxOutputLines: 200,
			SandboxProfile: "local",
		},
		Audit: AuditConfig{Sink: "stdout"},
		Approvals: ApprovalsConfig{
			Enabled:    true,
			StorePath:  filepath.Join(dir, "approvals.db"),
			TTLSeconds: 600,
			TeamsToken: "teams-token-1",
		},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "janus",
			Environment: "dev",
			APIKeys:     map[string]string{"k": "system"},
			AgentSecrets: map[string]string{
				"janus": "agent-secret",
			},
		},
	}, recorder, now)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Shutdown(context.Background()) })
	approvalID := createPendingApproval(t, gw)

	w := httptest.NewRecorder()
	payload := `{"approval_id":"` + approvalID + `","decision":"APPROVE","user_aad_id":"A1","conversation_id":"T1","extra":1}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/teams/approvals", strings.NewReader(payload))
	req.Header.Set("X-Janus-Teams-Token", "teams-token-1")
	gw.handleTeamsApprovalWebhook(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	payload = `{"approval_id":"` + approvalID + `","decision":"APPROVE","user_aad_id":"A1","conversation_id":"T1"}`
	req = httptest.NewRequest(http.MethodPost, "/webhooks/teams/approvals", strings.NewReader(payload))
	req.Header.Set("X-Janus-Teams-Token", "teams-token-1")
	gw.handleTeamsApprovalWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func createPendingApproval(t *testing.T, gw *Gateway) string {
	t.Helper()
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.write",
		Resource:      "file://workspace/out.txt",
		Params:        []byte(`{"content":"hello"}`),
		TraceID:       "trace1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "janus", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := gw.service.Process(act)
	if err != nil {
		t.Fatalf("process action: %v", err)
	}
	if resp.ApprovalID == "" {
		t.Fatal("expected pending approval id")
	}
	return resp.ApprovalID
}

var _ audit.Recorder = (*recordSink)(nil)
