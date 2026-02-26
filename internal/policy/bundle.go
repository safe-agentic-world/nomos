package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

func LoadBundle(path string) (Bundle, error) {
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
	sum := sha256.Sum256(data)
	bundle.Hash = hex.EncodeToString(sum[:])
	return bundle, nil
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
