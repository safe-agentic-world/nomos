package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
	if report.PolicyBundleHash == "" {
		t.Fatal("expected policy bundle hash")
	}
}

func TestRunMissingBundleNotReady(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, filepath.Join(dir, "missing.json"), true, dir)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
}

func TestRunMalformedBundleNotReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":`), 0o600); err != nil {
		t.Fatalf("write malformed bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
}

func TestReportJSONDeterministic(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir)

	r1, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run #1: %v", err)
	}
	r2, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run #2: %v", err)
	}
	j1, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	j2, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("expected deterministic json output\n1=%s\n2=%s", string(j1), string(j2))
	}
}

func writeConfig(t *testing.T, path, bundlePath string, mcpEnabled bool, workspaceRoot string) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{
			"listen":    ":8080",
			"transport": "http",
		},
		"runtime": map[string]any{"stateless_mode": false},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
		},
		"executor": map[string]any{
			"sandbox_enabled": false,
			"workspace_root":  workspaceRoot,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp":         map[string]any{"enabled": mcpEnabled},
		"upstream":    map[string]any{"routes": []any{}},
		"approvals":   map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":       "system",
			"agent":           "nomos",
			"environment":     "dev",
			"api_keys":        map[string]any{"dev-api-key": "system"},
			"service_secrets": map[string]any{},
			"agent_secrets":   map[string]any{"nomos": "dev-agent-secret"},
			"oidc":            map[string]any{"enabled": false, "issuer": "", "audience": "", "public_key_path": ""},
		},
		"redaction": map[string]any{"patterns": []any{}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
