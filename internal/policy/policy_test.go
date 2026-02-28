package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

func TestPolicyAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},{"id":"deny-secret","action_type":"fs.read","resource":"file://workspace/**/secret.txt","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	allowDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/README.md",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if allowDecision.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", allowDecision.Decision)
	}
	denyDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/foo/secret.txt",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if denyDecision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", denyDecision.Decision)
	}
}

func TestPolicyRequireApproval(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"approve-net","action_type":"net.http_request","resource":"url://example.com/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if decision.Decision != DecisionRequireApproval {
		t.Fatalf("expected require_approval, got %s", decision.Decision)
	}
}

func TestPolicyMatchesPrincipalsAndRiskFlags(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-net","action_type":"net.http_request","resource":"url://example.com/**","decision":"ALLOW","principals":["svc1"],"agents":["nomos"],"environments":["prod"],"risk_flags":["risk.net"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "svc1",
		Agent:       "nomos",
		Environment: "prod",
		Params:      []byte(`{}`),
	})
	if decision.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", decision.Decision)
	}
	denyDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "svc2",
		Agent:       "nomos",
		Environment: "prod",
		Params:      []byte(`{}`),
	})
	if denyDecision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", denyDecision.Decision)
	}
}

func TestPolicyBundleHashIncluded(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/README.md",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if decision.PolicyBundleHash == "" {
		t.Fatal("expected policy bundle hash")
	}
}

func TestPolicyExplainDenyWinsReportsOnlyDenyRules(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{ID: "allow-net", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionAllow},
			{ID: "deny-a", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionDeny},
			{ID: "deny-b", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionDeny},
		},
	}
	explanation := NewEngine(bundle).Explain(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if explanation.Decision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", explanation.Decision.Decision)
	}
	if len(explanation.DenyRules) != 2 {
		t.Fatalf("expected 2 deny rules, got %+v", explanation.DenyRules)
	}
	if explanation.DenyRules[0].RuleID != "deny-a" || explanation.DenyRules[1].RuleID != "deny-b" {
		t.Fatalf("expected sorted deny rules, got %+v", explanation.DenyRules)
	}
	if len(explanation.AllowRuleIDs) != 1 || explanation.AllowRuleIDs[0] != "allow-net" {
		t.Fatalf("expected allow rule ids retained for preview only, got %+v", explanation.AllowRuleIDs)
	}
}
