package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Gateway   GatewayConfig   `json:"gateway"`
	Policy    PolicyConfig    `json:"policy"`
	Executor  ExecutorConfig  `json:"executor"`
	Audit     AuditConfig     `json:"audit"`
	MCP       MCPConfig       `json:"mcp"`
	Upstream  UpstreamConfig  `json:"upstream"`
	Approvals ApprovalsConfig `json:"approvals"`
	Identity  IdentityConfig  `json:"identity"`
	Redaction RedactionConfig `json:"redaction"`
}

type GatewayConfig struct {
	Listen    string `json:"listen"`
	Transport string `json:"transport"`
}

type PolicyConfig struct {
	BundlePath string `json:"policy_bundle_path"`
}

type ExecutorConfig struct {
	SandboxEnabled bool   `json:"sandbox_enabled"`
	WorkspaceRoot  string `json:"workspace_root"`
	MaxOutputBytes int    `json:"max_output_bytes"`
	MaxOutputLines int    `json:"max_output_lines"`
	SandboxProfile string `json:"sandbox_profile"`
}

type AuditConfig struct {
	Sink string `json:"sink"`
}

type RedactionConfig struct {
	Patterns []string `json:"patterns"`
}

type MCPConfig struct {
	Enabled bool `json:"enabled"`
}

type UpstreamConfig struct {
	Routes []string `json:"routes"`
}

type ApprovalsConfig struct {
	Enabled bool `json:"enabled"`
}

type IdentityConfig struct {
	Principal      string            `json:"principal"`
	Agent          string            `json:"agent"`
	Environment    string            `json:"environment"`
	APIKeys        map[string]string `json:"api_keys"`
	ServiceSecrets map[string]string `json:"service_secrets"`
	AgentSecrets   map[string]string `json:"agent_secrets"`
}

func LoadConfig(path string, getenv func(string) string, policyBundleOverride string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("config contains trailing data")
	}

	ApplyEnvOverrides(&cfg, getenv)
	if policyBundleOverride != "" {
		cfg.Policy.BundlePath = policyBundleOverride
	}

	if err := cfg.SetDefaults(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) SetDefaults() error {
	if c.Gateway.Listen == "" {
		c.Gateway.Listen = ":8080"
	}
	if c.Gateway.Transport == "" {
		c.Gateway.Transport = "http"
	}
	if c.Audit.Sink == "" {
		c.Audit.Sink = "stdout"
	}
	if c.Executor.WorkspaceRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		c.Executor.WorkspaceRoot = cwd
	}
	if c.Executor.MaxOutputBytes == 0 {
		c.Executor.MaxOutputBytes = 64 * 1024
	}
	if c.Executor.MaxOutputLines == 0 {
		c.Executor.MaxOutputLines = 200
	}
	if c.Executor.SandboxProfile == "" {
		if c.Executor.SandboxEnabled {
			c.Executor.SandboxProfile = "local"
		} else {
			c.Executor.SandboxProfile = "none"
		}
	}
	return nil
}

func (c Config) Validate() error {
	var errs []string
	if c.Gateway.Listen == "" {
		errs = append(errs, "gateway.listen is required")
	}
	if c.Gateway.Transport != "http" {
		errs = append(errs, "gateway.transport must be \"http\" for M0")
	}
	if c.Identity.Principal == "" {
		errs = append(errs, "identity.principal is required")
	}
	if c.Identity.Agent == "" {
		errs = append(errs, "identity.agent is required")
	}
	if c.Identity.Environment == "" {
		errs = append(errs, "identity.environment is required")
	}
	if len(c.Identity.APIKeys) == 0 && len(c.Identity.ServiceSecrets) == 0 {
		errs = append(errs, "identity.api_keys or identity.service_secrets is required")
	}
	if len(c.Identity.AgentSecrets) == 0 {
		errs = append(errs, "identity.agent_secrets is required")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if c.Policy.BundlePath == "" {
		return errors.New("policy.policy_bundle_path is required")
	}
	if _, err := os.Stat(c.Policy.BundlePath); err != nil {
		return fmt.Errorf("policy bundle path invalid: %w", err)
	}
	return nil
}

func ApplyEnvOverrides(cfg *Config, getenv func(string) string) {
	if v := getenv("JANUS_GATEWAY_LISTEN"); v != "" {
		cfg.Gateway.Listen = v
	}
	if v := getenv("JANUS_GATEWAY_TRANSPORT"); v != "" {
		cfg.Gateway.Transport = v
	}
	if v := getenv("JANUS_POLICY_BUNDLE_PATH"); v != "" {
		cfg.Policy.BundlePath = v
	}
	if v := getenv("JANUS_EXECUTOR_SANDBOX_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Executor.SandboxEnabled = parsed
		}
	}
	if v := getenv("JANUS_EXECUTOR_SANDBOX_PROFILE"); v != "" {
		cfg.Executor.SandboxProfile = v
	}
	if v := getenv("JANUS_EXECUTOR_WORKSPACE_ROOT"); v != "" {
		cfg.Executor.WorkspaceRoot = v
	}
	if v := getenv("JANUS_EXECUTOR_MAX_OUTPUT_BYTES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Executor.MaxOutputBytes = parsed
		}
	}
	if v := getenv("JANUS_EXECUTOR_MAX_OUTPUT_LINES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Executor.MaxOutputLines = parsed
		}
	}
	if v := getenv("JANUS_AUDIT_SINK"); v != "" {
		cfg.Audit.Sink = v
	}
	if v := getenv("JANUS_REDACTION_PATTERNS"); v != "" {
		cfg.Redaction.Patterns = splitList(v)
	}
	if v := getenv("JANUS_MCP_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.MCP.Enabled = parsed
		}
	}
	if v := getenv("JANUS_UPSTREAM_ROUTES"); v != "" {
		cfg.Upstream.Routes = splitList(v)
	}
	if v := getenv("JANUS_APPROVALS_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Approvals.Enabled = parsed
		}
	}
	if v := getenv("JANUS_IDENTITY_PRINCIPAL"); v != "" {
		cfg.Identity.Principal = v
	}
	if v := getenv("JANUS_IDENTITY_AGENT"); v != "" {
		cfg.Identity.Agent = v
	}
	if v := getenv("JANUS_IDENTITY_ENVIRONMENT"); v != "" {
		cfg.Identity.Environment = v
	}
	if v := getenv("JANUS_IDENTITY_API_KEY"); v != "" {
		if cfg.Identity.APIKeys == nil {
			cfg.Identity.APIKeys = map[string]string{}
		}
		cfg.Identity.APIKeys[v] = cfg.Identity.Principal
	}
	if v := getenv("JANUS_IDENTITY_AGENT_SECRET"); v != "" {
		if cfg.Identity.AgentSecrets == nil {
			cfg.Identity.AgentSecrets = map[string]string{}
		}
		cfg.Identity.AgentSecrets[cfg.Identity.Agent] = v
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseBool(value string) (bool, bool) {
	parsed, err := strconv.ParseBool(value)
	return parsed, err == nil
}
