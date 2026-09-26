package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeToolPinsTestConfig(t *testing.T, dir string, upstream map[string]any) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	data := mustMarshal(map[string]any{
		"gateway":   map[string]any{"listen": ":8080", "transport": "http"},
		"policy":    map[string]any{"policy_bundle_path": "bundle.json"},
		"executor":  map[string]any{"sandbox_enabled": false, "workspace_root": dir},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": true},
		"upstream":  upstream,
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

func TestLoadConfigToolPinsDefaultsNextToConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := writeToolPinsTestConfig(t, dir, map[string]any{"routes": []any{}})
	cfg, err := LoadConfig(configPath, func(string) string { return "" }, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Upstream.ToolPins.Mode != "record" {
		t.Fatalf("expected default tool pin mode record, got %q", cfg.Upstream.ToolPins.Mode)
	}
	if want := filepath.Join(dir, "upstream-tool-pins.json"); cfg.Upstream.ToolPins.File != want {
		t.Fatalf("expected default pin file next to the config (%s), got %s", want, cfg.Upstream.ToolPins.File)
	}
	if _, err := os.Stat(cfg.Upstream.ToolPins.File); !os.IsNotExist(err) {
		t.Fatalf("expected config loading not to create the pin file, got %v", err)
	}
}

func TestLoadConfigToolPinsResolvesRelativeFileAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	configPath := writeToolPinsTestConfig(t, dir, map[string]any{
		"routes":    []any{},
		"tool_pins": map[string]any{"file": "./state/tool-pins.json", "mode": "strict"},
	})
	cfg, err := LoadConfig(configPath, func(string) string { return "" }, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Upstream.ToolPins.Mode != "strict" {
		t.Fatalf("expected strict mode, got %q", cfg.Upstream.ToolPins.Mode)
	}
	if want := filepath.Join(dir, "state", "tool-pins.json"); cfg.Upstream.ToolPins.File != want {
		t.Fatalf("expected config-relative pin file %s, got %s", want, cfg.Upstream.ToolPins.File)
	}

	legacyPath := writeToolPinsTestConfig(t, t.TempDir(), map[string]any{
		"routes":    []any{"https://legacy.example.com"},
		"tool_pins": map[string]any{"mode": "off"},
	})
	cfg, err = LoadConfig(legacyPath, func(string) string { return "" }, "")
	if err != nil {
		t.Fatalf("load legacy config: %v", err)
	}
	if cfg.Upstream.ToolPins.Mode != "off" || len(cfg.Upstream.Routes) != 1 {
		t.Fatalf("expected legacy routes with tool pins off, got %+v", cfg.Upstream)
	}
}

func TestLoadConfigRejectsInvalidToolPins(t *testing.T) {
	cases := []struct {
		name     string
		upstream map[string]any
		want     string
	}{
		{
			name:     "unknown mode",
			upstream: map[string]any{"routes": []any{}, "tool_pins": map[string]any{"mode": "trust"}},
			want:     "upstream.tool_pins.mode must be one of record, strict, off",
		},
		{
			name:     "unknown field",
			upstream: map[string]any{"routes": []any{}, "tool_pins": map[string]any{"mode": "record", "path": "pins.json"}},
			want:     "unknown field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeToolPinsTestConfig(t, t.TempDir(), tc.upstream)
			_, err := LoadConfig(configPath, func(string) string { return "" }, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pins-dir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	configPath := writeToolPinsTestConfig(t, dir, map[string]any{"routes": []any{}, "tool_pins": map[string]any{"file": "pins-dir"}})
	if _, err := LoadConfig(configPath, func(string) string { return "" }, ""); err == nil || !strings.Contains(err.Error(), "must be a file, not a directory") {
		t.Fatalf("expected directory pin file to be rejected, got %v", err)
	}
}
