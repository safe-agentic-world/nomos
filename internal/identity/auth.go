package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

type Authenticator struct {
	config AuthConfig
}

func NewAuthenticator(config AuthConfig) *Authenticator {
	return &Authenticator{config: config}
}

func (a *Authenticator) Verify(req *http.Request, body []byte) (VerifiedIdentity, error) {
	if a.config.Environment == "" {
		return VerifiedIdentity{}, errors.New("environment is required")
	}
	principal, err := a.verifyPrincipal(req, body)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	agent, err := a.verifyAgent(req, body)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	return VerifiedIdentity{
		Principal:   principal,
		Agent:       agent,
		Environment: a.config.Environment,
	}, nil
}

func (a *Authenticator) verifyPrincipal(req *http.Request, body []byte) (string, error) {
	if principal, ok := a.verifyAPIKey(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifyServiceSignature(req, body); ok {
		return principal, nil
	}
	return "", errors.New("principal authentication failed")
}

func (a *Authenticator) verifyAPIKey(req *http.Request) (string, bool) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	key := strings.TrimSpace(parts[1])
	if key == "" {
		return "", false
	}
	principal, ok := a.config.APIKeys[key]
	return principal, ok
}

func (a *Authenticator) verifyServiceSignature(req *http.Request, body []byte) (string, bool) {
	serviceID := strings.TrimSpace(req.Header.Get("X-Janus-Service-Id"))
	signature := strings.TrimSpace(req.Header.Get("X-Janus-Service-Signature"))
	if serviceID == "" || signature == "" {
		return "", false
	}
	secret, ok := a.config.ServiceSecrets[serviceID]
	if !ok {
		return "", false
	}
	expected := hmacSHA256Hex([]byte(secret), body)
	return serviceID, hmac.Equal([]byte(signature), []byte(expected))
}

func (a *Authenticator) verifyAgent(req *http.Request, body []byte) (string, error) {
	agentID := strings.TrimSpace(req.Header.Get("X-Janus-Agent-Id"))
	signature := strings.TrimSpace(req.Header.Get("X-Janus-Agent-Signature"))
	if agentID == "" || signature == "" {
		return "", errors.New("agent authentication failed")
	}
	secret, ok := a.config.AgentSecrets[agentID]
	if !ok {
		return "", errors.New("agent authentication failed")
	}
	expected := hmacSHA256Hex([]byte(secret), body)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", errors.New("agent authentication failed")
	}
	return agentID, nil
}

func hmacSHA256Hex(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
