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
	Gateway     GatewayConfig     `json:"gateway"`
	Runtime     RuntimeConfig     `json:"runtime"`
	Policy      PolicyConfig      `json:"policy"`
	Executor    ExecutorConfig    `json:"executor"`
	Credentials CredentialsConfig `json:"credentials"`
	Audit       AuditConfig       `json:"audit"`
	MCP         MCPConfig         `json:"mcp"`
	Upstream    UpstreamConfig    `json:"upstream"`
	Approvals   ApprovalsConfig   `json:"approvals"`
	Identity    IdentityConfig    `json:"identity"`
	Redaction   RedactionConfig   `json:"redaction"`
}

type GatewayConfig struct {
	Listen           string    `json:"listen"`
	Transport        string    `json:"transport"`
	ConcurrencyLimit int       `json:"concurrency_limit"`
	RateLimitPerMin  int       `json:"rate_limit_per_minute"`
	CircuitFailures  int       `json:"circuit_breaker_failures"`
	CircuitCooldownS int       `json:"circuit_breaker_cooldown_seconds"`
	TLS              TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled      bool   `json:"enabled"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
	RequireMTLS  bool   `json:"require_mtls"`
}

type RuntimeConfig struct {
	StatelessMode bool `json:"stateless_mode"`
}

type PolicyConfig struct {
	BundlePath       string `json:"policy_bundle_path"`
	VerifySignatures bool   `json:"verify_signatures"`
	SignaturePath    string `json:"signature_path"`
	PublicKeyPath    string `json:"public_key_path"`
}

type ExecutorConfig struct {
	SandboxEnabled bool   `json:"sandbox_enabled"`
	WorkspaceRoot  string `json:"workspace_root"`
	MaxOutputBytes int    `json:"max_output_bytes"`
	MaxOutputLines int    `json:"max_output_lines"`
	SandboxProfile string `json:"sandbox_profile"`
}

type CredentialsConfig struct {
	Enabled bool               `json:"enabled"`
	Secrets []CredentialSecret `json:"secrets"`
}

type CredentialSecret struct {
	ID         string `json:"id"`
	EnvKey     string `json:"env_key"`
	Value      string `json:"value"`
	TTLSeconds int    `json:"ttl_seconds"`
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
	Enabled      bool   `json:"enabled"`
	StorePath    string `json:"store_path"`
	TTLSeconds   int    `json:"ttl_seconds"`
	WebhookToken string `json:"webhook_token"`
	SlackToken   string `json:"slack_token"`
	TeamsToken   string `json:"teams_token"`
}

type IdentityConfig struct {
	Principal      string            `json:"principal"`
	Agent          string            `json:"agent"`
	Environment    string            `json:"environment"`
	APIKeys        map[string]string `json:"api_keys"`
	ServiceSecrets map[string]string `json:"service_secrets"`
	AgentSecrets   map[string]string `json:"agent_secrets"`
	OIDC           OIDCConfig        `json:"oidc"`
}

type OIDCConfig struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	PublicKeyPath string `json:"public_key_path"`
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
	if c.Gateway.ConcurrencyLimit == 0 {
		c.Gateway.ConcurrencyLimit = 32
	}
	if c.Gateway.RateLimitPerMin == 0 {
		c.Gateway.RateLimitPerMin = 120
	}
	if c.Gateway.CircuitFailures == 0 {
		c.Gateway.CircuitFailures = 5
	}
	if c.Gateway.CircuitCooldownS == 0 {
		c.Gateway.CircuitCooldownS = 60
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
	if c.Credentials.Enabled && len(c.Credentials.Secrets) == 0 {
		c.Credentials.Enabled = false
	}
	if c.Approvals.Enabled {
		if c.Approvals.StorePath == "" {
			c.Approvals.StorePath = "janus-approvals.db"
		}
		if c.Approvals.TTLSeconds == 0 {
			c.Approvals.TTLSeconds = 900
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
	if c.Gateway.ConcurrencyLimit <= 0 {
		errs = append(errs, "gateway.concurrency_limit must be > 0")
	}
	if c.Gateway.RateLimitPerMin <= 0 {
		errs = append(errs, "gateway.rate_limit_per_minute must be > 0")
	}
	if c.Gateway.CircuitFailures <= 0 {
		errs = append(errs, "gateway.circuit_breaker_failures must be > 0")
	}
	if c.Gateway.CircuitCooldownS <= 0 {
		errs = append(errs, "gateway.circuit_breaker_cooldown_seconds must be > 0")
	}
	if c.Gateway.TLS.Enabled {
		if c.Gateway.TLS.CertFile == "" || c.Gateway.TLS.KeyFile == "" {
			errs = append(errs, "gateway.tls.cert_file and gateway.tls.key_file are required when tls.enabled is true")
		}
		if c.Gateway.TLS.RequireMTLS && c.Gateway.TLS.ClientCAFile == "" {
			errs = append(errs, "gateway.tls.client_ca_file is required when tls.require_mtls is true")
		}
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
	if len(c.Identity.APIKeys) == 0 && len(c.Identity.ServiceSecrets) == 0 && !c.Identity.OIDC.Enabled {
		errs = append(errs, "identity.api_keys or identity.service_secrets or identity.oidc.enabled is required")
	}
	if len(c.Identity.AgentSecrets) == 0 {
		errs = append(errs, "identity.agent_secrets is required")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if c.Identity.OIDC.Enabled {
		if c.Identity.OIDC.Issuer == "" || c.Identity.OIDC.Audience == "" || c.Identity.OIDC.PublicKeyPath == "" {
			return errors.New("identity.oidc.issuer, identity.oidc.audience, and identity.oidc.public_key_path are required when oidc.enabled is true")
		}
		if _, err := os.Stat(c.Identity.OIDC.PublicKeyPath); err != nil {
			return fmt.Errorf("oidc public key path invalid: %w", err)
		}
	}
	if c.Runtime.StatelessMode {
		if c.Approvals.Enabled {
			return errors.New("approvals must be disabled in runtime.stateless_mode")
		}
		if strings.Contains(c.Audit.Sink, "sqlite:") || strings.Contains(c.Audit.Sink, "sqlite://") {
			return errors.New("sqlite audit sink is not allowed in runtime.stateless_mode")
		}
	}
	if c.Credentials.Enabled {
		if len(c.Credentials.Secrets) == 0 {
			return errors.New("credentials.secrets is required when credentials.enabled is true")
		}
		for _, s := range c.Credentials.Secrets {
			if s.ID == "" || s.EnvKey == "" || s.Value == "" {
				return errors.New("credentials secret id/env_key/value are required")
			}
			if s.TTLSeconds <= 0 {
				return errors.New("credentials secret ttl_seconds must be > 0")
			}
		}
	}
	if c.Approvals.Enabled {
		if c.Approvals.StorePath == "" {
			return errors.New("approvals.store_path is required when approvals are enabled")
		}
		if c.Approvals.TTLSeconds <= 0 {
			return errors.New("approvals.ttl_seconds must be > 0 when approvals are enabled")
		}
	}
	if c.Policy.BundlePath == "" {
		return errors.New("policy.policy_bundle_path is required")
	}
	if _, err := os.Stat(c.Policy.BundlePath); err != nil {
		return fmt.Errorf("policy bundle path invalid: %w", err)
	}
	if c.Policy.VerifySignatures {
		if c.Policy.SignaturePath == "" || c.Policy.PublicKeyPath == "" {
			return errors.New("policy.signature_path and policy.public_key_path are required when policy.verify_signatures is true")
		}
		if _, err := os.Stat(c.Policy.SignaturePath); err != nil {
			return fmt.Errorf("policy signature path invalid: %w", err)
		}
		if _, err := os.Stat(c.Policy.PublicKeyPath); err != nil {
			return fmt.Errorf("policy public key path invalid: %w", err)
		}
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
	if v := getenv("JANUS_GATEWAY_CONCURRENCY_LIMIT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.ConcurrencyLimit = parsed
		}
	}
	if v := getenv("JANUS_GATEWAY_RATE_LIMIT_PER_MINUTE"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.RateLimitPerMin = parsed
		}
	}
	if v := getenv("JANUS_GATEWAY_CIRCUIT_BREAKER_FAILURES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.CircuitFailures = parsed
		}
	}
	if v := getenv("JANUS_GATEWAY_CIRCUIT_BREAKER_COOLDOWN_SECONDS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.CircuitCooldownS = parsed
		}
	}
	if v := getenv("JANUS_RUNTIME_STATELESS_MODE"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.StatelessMode = parsed
		}
	}
	if v := getenv("JANUS_POLICY_BUNDLE_PATH"); v != "" {
		cfg.Policy.BundlePath = v
	}
	if v := getenv("JANUS_POLICY_VERIFY_SIGNATURES"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Policy.VerifySignatures = parsed
		}
	}
	if v := getenv("JANUS_POLICY_SIGNATURE_PATH"); v != "" {
		cfg.Policy.SignaturePath = v
	}
	if v := getenv("JANUS_POLICY_PUBLIC_KEY_PATH"); v != "" {
		cfg.Policy.PublicKeyPath = v
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
	if v := getenv("JANUS_CREDENTIALS_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Credentials.Enabled = parsed
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
	if v := getenv("JANUS_APPROVALS_STORE_PATH"); v != "" {
		cfg.Approvals.StorePath = v
	}
	if v := getenv("JANUS_APPROVALS_TTL_SECONDS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Approvals.TTLSeconds = parsed
		}
	}
	if v := getenv("JANUS_APPROVALS_WEBHOOK_TOKEN"); v != "" {
		cfg.Approvals.WebhookToken = v
	}
	if v := getenv("JANUS_APPROVALS_SLACK_TOKEN"); v != "" {
		cfg.Approvals.SlackToken = v
	}
	if v := getenv("JANUS_APPROVALS_TEAMS_TOKEN"); v != "" {
		cfg.Approvals.TeamsToken = v
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
	if v := getenv("JANUS_IDENTITY_OIDC_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Identity.OIDC.Enabled = parsed
		}
	}
	if v := getenv("JANUS_IDENTITY_OIDC_ISSUER"); v != "" {
		cfg.Identity.OIDC.Issuer = v
	}
	if v := getenv("JANUS_IDENTITY_OIDC_AUDIENCE"); v != "" {
		cfg.Identity.OIDC.Audience = v
	}
	if v := getenv("JANUS_IDENTITY_OIDC_PUBLIC_KEY_PATH"); v != "" {
		cfg.Identity.OIDC.PublicKeyPath = v
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
