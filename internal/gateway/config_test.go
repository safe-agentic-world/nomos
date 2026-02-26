package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAppliesEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	overridePath := filepath.Join(dir, "bundle-override.json")
	if err := os.WriteFile(overridePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write override bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
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

	env := map[string]string{
		"JANUS_GATEWAY_LISTEN":        "127.0.0.1:0",
		"JANUS_MCP_ENABLED":           "true",
		"JANUS_IDENTITY_PRINCIPAL":    "override",
		"JANUS_IDENTITY_API_KEY":      "override-key",
		"JANUS_IDENTITY_AGENT_SECRET": "override-agent-secret",
		"JANUS_POLICY_BUNDLE_PATH":    overridePath,
	}
	cfg, err := LoadConfig(path, func(key string) string {
		return env[key]
	}, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Gateway.Listen != "127.0.0.1:0" {
		t.Fatalf("expected listen override, got %s", cfg.Gateway.Listen)
	}
	if !cfg.MCP.Enabled {
		t.Fatal("expected mcp.enabled override")
	}
	if cfg.Identity.Principal != "override" {
		t.Fatalf("expected principal override, got %s", cfg.Identity.Principal)
	}
	if cfg.Identity.APIKeys["override-key"] != "override" {
		t.Fatal("expected api key override")
	}
	if cfg.Identity.AgentSecrets["janus"] != "override-agent-secret" {
		t.Fatal("expected agent secret override")
	}
	if cfg.Policy.BundlePath != overridePath {
		t.Fatalf("expected bundle override, got %s", cfg.Policy.BundlePath)
	}
}

func TestLoadConfigRequiresPolicyBundlePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{},
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
	_, err := LoadConfig(path, os.Getenv, "")
	if err == nil {
		t.Fatal("expected policy bundle path error")
	}
}
