package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadBundleYAMLJSONParity(t *testing.T) {
	jsonBundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "policies", "safe.json")))
	if err != nil {
		t.Fatalf("load json bundle: %v", err)
	}
	yamlBundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("load yaml bundle: %v", err)
	}
	if jsonBundle.Hash != yamlBundle.Hash {
		t.Fatalf("expected equal hashes, got json=%s yaml=%s", jsonBundle.Hash, yamlBundle.Hash)
	}

	fixtures := []normalize.NormalizedAction{
		{ActionType: "fs.read", Resource: "file://workspace/README.md", Principal: "system", Agent: "nomos", Environment: "dev"},
		{ActionType: "fs.write", Resource: "file://workspace/docs/guide.md", Principal: "system", Agent: "nomos", Environment: "dev"},
		{ActionType: "process.exec", Resource: "file://workspace/", Principal: "system", Agent: "nomos", Environment: "dev"},
	}
	jsonEngine := NewEngine(jsonBundle)
	yamlEngine := NewEngine(yamlBundle)
	for _, fixture := range fixtures {
		jsonDecision := jsonEngine.Evaluate(fixture)
		yamlDecision := yamlEngine.Evaluate(fixture)
		jsonBytes, err := json.Marshal(jsonDecision)
		if err != nil {
			t.Fatalf("marshal json decision: %v", err)
		}
		yamlBytes, err := json.Marshal(yamlDecision)
		if err != nil {
			t.Fatalf("marshal yaml decision: %v", err)
		}
		if string(jsonBytes) != string(yamlBytes) {
			t.Fatalf("expected identical decisions for %+v\njson=%s\nyaml=%s", fixture, string(jsonBytes), string(yamlBytes))
		}
	}
}

func TestLoadBundleYMLExtensionSupported(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("read source yaml: %v", err)
	}
	ymlPath := filepath.Join(dir, "safe.yml")
	if err := os.WriteFile(ymlPath, data, 0o600); err != nil {
		t.Fatalf("write yml bundle: %v", err)
	}
	if _, err := LoadBundle(ymlPath); err != nil {
		t.Fatalf("expected .yml bundle to load, got %v", err)
	}
}

func TestLoadBundleYAMLRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	topLevelPath := filepath.Join(dir, "top.yaml")
	topLevel := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    resource: file://workspace/README.md\n    decision: ALLOW\nextra_field: nope\n"
	if err := os.WriteFile(topLevelPath, []byte(topLevel), 0o600); err != nil {
		t.Fatalf("write top-level yaml: %v", err)
	}
	if _, err := LoadBundle(topLevelPath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected unknown top-level field error, got %v", err)
	}

	nestedPath := filepath.Join(dir, "nested.yaml")
	nested := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    resource: file://workspace/README.md\n    decision: ALLOW\n    unexpected_nested: nope\n"
	if err := os.WriteFile(nestedPath, []byte(nested), 0o600); err != nil {
		t.Fatalf("write nested yaml: %v", err)
	}
	if _, err := LoadBundle(nestedPath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected unknown nested field error, got %v", err)
	}
}

func TestLoadBundleYAMLRejectsDuplicateKeys(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "dup.yaml")
	data := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    action_type: fs.write\n    resource: file://workspace/README.md\n    decision: ALLOW\n"
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write duplicate yaml: %v", err)
	}
	if _, err := LoadBundle(bundlePath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate yaml key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestLoadBundleHashGoldenVectorForSafe(t *testing.T) {
	bundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("load yaml bundle: %v", err)
	}
	const expected = "b7e8173c39d43e39188b7544fd27b97bd34800237e9d1afe6bbd9866962b07c9"
	if bundle.Hash != expected {
		t.Fatalf("expected hash %s, got %s", expected, bundle.Hash)
	}
}
