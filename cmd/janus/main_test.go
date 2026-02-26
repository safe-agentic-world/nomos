package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/janus/internal/gateway"
)

func TestResolveMCPInvocationFlagPrecedenceOverEnv(t *testing.T) {
	dir := t.TempDir()
	flagConfig := filepath.Join(dir, "flag-config.json")
	flagBundle := filepath.Join(dir, "flag-bundle.json")
	got, err := resolveMCPInvocation(flagConfig, flagBundle, "warn", true, func(string) string {
		return "ignored"
	})
	if err != nil {
		t.Fatalf("resolve mcp: %v", err)
	}
	if got.LogLevel != "warn" || got.LogLevelSource != "flag" {
		t.Fatalf("expected flag log level precedence, got %+v", got)
	}
	if !strings.HasSuffix(got.ConfigPath, "flag-config.json") || !strings.HasSuffix(got.PolicyBundle, "flag-bundle.json") {
		t.Fatalf("expected flag paths, got %+v", got)
	}
	if !got.Quiet {
		t.Fatal("expected quiet=true")
	}
}

func TestResolveMCPInvocationEnvFallback(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"JANUS_CONFIG":        filepath.Join(dir, "env-config.json"),
		"JANUS_POLICY_BUNDLE": filepath.Join(dir, "env-bundle.json"),
		"JANUS_LOG_LEVEL":     "debug",
	}
	got, err := resolveMCPInvocation("", "", "", false, func(key string) string {
		return env[key]
	})
	if err != nil {
		t.Fatalf("resolve mcp: %v", err)
	}
	if got.LogLevel != "debug" || got.LogLevelSource != "env" {
		t.Fatalf("expected env log level fallback, got %+v", got)
	}
	if !strings.HasSuffix(got.ConfigPath, "env-config.json") || !strings.HasSuffix(got.PolicyBundle, "env-bundle.json") {
		t.Fatalf("expected env paths, got %+v", got)
	}
}

func TestResolveMCPInvocationRequiresConfig(t *testing.T) {
	_, err := resolveMCPInvocation("", "", "", false, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if !strings.Contains(err.Error(), "--config/-c") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigFailsClosedWithoutBundle(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := `{
  "gateway":{"listen":":8080","transport":"http"},
  "runtime":{"stateless_mode":false},
  "policy":{"policy_bundle_path":""},
  "executor":{"sandbox_enabled":false,"workspace_root":"` + filepath.ToSlash(dir) + `"},
  "credentials":{"enabled":false,"secrets":[]},
  "audit":{"sink":"stdout"},
  "mcp":{"enabled":true},
  "upstream":{"routes":[]},
  "approvals":{"enabled":false},
  "identity":{
    "principal":"system",
    "agent":"janus",
    "environment":"dev",
    "api_keys":{"dev-api-key":"system"},
    "service_secrets":{},
    "agent_secrets":{"janus":"dev-agent-secret"},
    "oidc":{"enabled":false,"issuer":"","audience":"","public_key_path":""}
  },
  "redaction":{"patterns":[]}
}`
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := gateway.LoadConfig(configPath, func(string) string { return "" }, "")
	if err == nil {
		t.Fatal("expected fail-closed config error")
	}
	if !strings.Contains(err.Error(), "policy.policy_bundle_path is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHelpTextStability(t *testing.T) {
	root := rootHelpText()
	mcp := mcpHelpText()
	if !strings.Contains(root, "janus mcp -c config.example.json -p policies/m1_5_minimal.json") {
		t.Fatalf("unexpected root help: %q", root)
	}
	if !strings.Contains(root, "doctor") {
		t.Fatalf("expected doctor command in root help: %q", root)
	}
	if !strings.Contains(mcp, "-c, --config") || !strings.Contains(mcp, "-p, --policy-bundle") || !strings.Contains(mcp, "-l, --log-level") || !strings.Contains(mcp, "-q, --quiet") {
		t.Fatalf("missing short/long flags in mcp help: %q", mcp)
	}
}

func TestDoctorExitCodesAndJSONDeterminism(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["janus"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, bundlePath, true, dir)

	var out1, err1 bytes.Buffer
	code1 := runDoctorCommand([]string{"-c", configPath, "--format", "json"}, &out1, &err1, func(string) string { return "" })
	if code1 != 0 {
		t.Fatalf("expected READY exit code 0, got %d stderr=%q", code1, err1.String())
	}
	var out2, err2 bytes.Buffer
	code2 := runDoctorCommand([]string{"--config", configPath, "--format", "json"}, &out2, &err2, func(string) string { return "" })
	if code2 != 0 {
		t.Fatalf("expected READY exit code 0, got %d stderr=%q", code2, err2.String())
	}
	if out1.String() != out2.String() {
		t.Fatalf("expected deterministic json output\n1=%s\n2=%s", out1.String(), out2.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out1.Bytes()), &parsed); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if parsed["overall_status"] != "READY" {
		t.Fatalf("expected READY, got %v", parsed["overall_status"])
	}
	if _, ok := parsed["engine_version"]; !ok {
		t.Fatal("expected engine_version in json output")
	}
}

func TestDoctorNotReadyExitCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, filepath.Join(dir, "missing.json"), true, dir)
	var out, errOut bytes.Buffer
	code := runDoctorCommand([]string{"-c", configPath}, &out, &errOut, func(string) string { return "" })
	if code != 1 {
		t.Fatalf("expected NOT_READY exit code 1, got %d", code)
	}
	if !strings.Contains(out.String(), "Result: NOT_READY") {
		t.Fatalf("expected NOT_READY summary, got: %q", out.String())
	}
}

func TestDoctorInvalidFormatInternalErrorCode(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["janus"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, bundlePath, true, dir)
	var out, errOut bytes.Buffer
	code := runDoctorCommand([]string{"-c", configPath, "--format", "yaml"}, &out, &errOut, func(string) string { return "" })
	if code != 2 {
		t.Fatalf("expected internal error exit code 2, got %d", code)
	}
}

func TestWriteRedactedLine(t *testing.T) {
	var out bytes.Buffer
	writeRedactedLine(&out, "authorization: Bearer abc.def.ghi")
	got := out.String()
	if strings.Contains(strings.ToLower(got), "authorization:") || strings.Contains(got, "abc.def.ghi") {
		t.Fatalf("expected redacted output, got: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
}

func writeDoctorTestConfig(t *testing.T, path, bundlePath string, mcpEnabled bool, workspaceRoot string) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"stateless_mode": false},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
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
			"agent":           "janus",
			"environment":     "dev",
			"api_keys":        map[string]any{"dev-api-key": "system"},
			"service_secrets": map[string]any{},
			"agent_secrets":   map[string]any{"janus": "dev-agent-secret"},
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
