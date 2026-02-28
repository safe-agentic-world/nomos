package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticatorAPIKeyAndAgent(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"key1": "principal1",
		},
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("secret1", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "principal1" || id.Agent != "agent1" || id.Environment != "dev" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestAuthenticatorServiceSignature(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		ServiceSecrets: map[string]string{
			"service1": "svc-secret",
		},
		AgentSecrets: map[string]string{
			"agent1": "agent-secret",
		},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("X-Nomos-Service-Id", "service1")
	req.Header.Set("X-Nomos-Service-Signature", hmacHex("svc-secret", body))
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "service1" || id.Agent != "agent1" || id.Environment != "prod" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestAuthenticatorRejectsMissingAgent(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"key1": "principal1",
		},
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("Authorization", "Bearer key1")
	_, err = auth.Verify(req, body)
	if err == nil {
		t.Fatal("expected agent auth failure")
	}
}

func hmacHex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
