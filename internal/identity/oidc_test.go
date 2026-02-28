package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthenticatorOIDC(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath := filepath.Join(t.TempDir(), "oidc_pub.pem")
	if err := os.WriteFile(pubPath, pemData, 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}

	auth, err := NewAuthenticator(AuthConfig{
		OIDCEnabled:       true,
		OIDCIssuer:        "https://issuer.example",
		OIDCAudience:      "nomos",
		OIDCPublicKeyPath: pubPath,
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}

	claims := jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "nomos",
		"sub": "oidc-user",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("secret1", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "oidc-user" {
		t.Fatalf("expected oidc-user principal, got %s", id.Principal)
	}
}
