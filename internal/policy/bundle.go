package policy

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Bundle struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
	Hash    string `json:"-"`
}

type Rule struct {
	ID           string         `json:"id"`
	ActionType   string         `json:"action_type"`
	Resource     string         `json:"resource"`
	Decision     string         `json:"decision"`
	Principals   []string       `json:"principals,omitempty"`
	Agents       []string       `json:"agents,omitempty"`
	Environments []string       `json:"environments,omitempty"`
	RiskFlags    []string       `json:"risk_flags,omitempty"`
	Obligations  map[string]any `json:"obligations,omitempty"`
}

type LoadOptions struct {
	VerifySignature bool
	SignaturePath   string
	PublicKeyPath   string
}

func LoadBundle(path string) (Bundle, error) {
	return LoadBundleWithOptions(path, LoadOptions{})
}

func LoadBundleWithOptions(path string, options LoadOptions) (Bundle, error) {
	if path == "" {
		return Bundle{}, errors.New("bundle path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("read bundle: %w", err)
	}
	var bundle Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Bundle{}, errors.New("bundle contains trailing data")
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	if options.VerifySignature {
		if err := verifyBundleSignature(data, options.SignaturePath, options.PublicKeyPath); err != nil {
			return Bundle{}, err
		}
	}
	sum := sha256.Sum256(data)
	bundle.Hash = hex.EncodeToString(sum[:])
	return bundle, nil
}

func verifyBundleSignature(bundleData []byte, signaturePath, publicKeyPath string) error {
	if signaturePath == "" || publicKeyPath == "" {
		return errors.New("signature and public key paths are required")
	}
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return errors.New("signature must be base64")
	}
	pubPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("invalid public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("invalid rsa public key")
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not rsa")
	}
	digest := sha256.Sum256(bundleData)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigRaw); err != nil {
		return errors.New("policy bundle signature verification failed")
	}
	return nil
}

func (b Bundle) Validate() error {
	if b.Version != "v1" {
		return errors.New("bundle version must be v1")
	}
	if len(b.Rules) == 0 {
		return errors.New("bundle rules are required")
	}
	seen := map[string]struct{}{}
	for _, rule := range b.Rules {
		if rule.ID == "" {
			return errors.New("rule id is required")
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.ActionType == "" {
			return fmt.Errorf("rule %s missing action_type", rule.ID)
		}
		if rule.Resource == "" {
			return fmt.Errorf("rule %s missing resource", rule.ID)
		}
		if rule.Decision != DecisionAllow && rule.Decision != DecisionDeny && rule.Decision != DecisionRequireApproval {
			return fmt.Errorf("rule %s has invalid decision", rule.ID)
		}
	}
	return nil
}
