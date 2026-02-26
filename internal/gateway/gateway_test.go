package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-developer-project/janus/internal/audit"
)

func TestGatewayStartAndShutdown(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": "127.0.0.1:0", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "janus",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"janus": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := gw.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown gateway: %v", err)
	}
}

type recordSink struct {
	events []audit.Event
}

func (r *recordSink) WriteEvent(event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func TestGatewayEmitsTraceEvents(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "janus",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
			AgentSecrets: map[string]string{
				"janus": "agent-secret",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Janus-Agent-Id", "janus")
	req.Header.Set("X-Janus-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if len(recorder.events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(recorder.events))
	}
	if recorder.events[0].EventType != "trace.start" {
		t.Fatalf("expected trace.start, got %s", recorder.events[0].EventType)
	}
	if recorder.events[2].EventType != "trace.end" {
		t.Fatalf("expected trace.end, got %s", recorder.events[2].EventType)
	}
	for _, event := range recorder.events {
		if event.TraceID != "trace1" {
			t.Fatalf("expected trace_id trace1, got %s", event.TraceID)
		}
	}
	decisionEvent := recorder.events[1]
	if decisionEvent.Principal != "system" || decisionEvent.Agent != "janus" || decisionEvent.Environment != "dev" {
		t.Fatalf("expected identity in audit event, got principal=%s agent=%s env=%s", decisionEvent.Principal, decisionEvent.Agent, decisionEvent.Environment)
	}
}

func hmacHex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
