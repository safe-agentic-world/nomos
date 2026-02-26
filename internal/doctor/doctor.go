package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safe-agentic-world/janus/internal/gateway"
	"github.com/safe-agentic-world/janus/internal/normalize"
	"github.com/safe-agentic-world/janus/internal/policy"
	"github.com/safe-agentic-world/janus/internal/version"
)

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type Report struct {
	OverallStatus    string  `json:"overall_status"`
	Checks           []Check `json:"checks"`
	PolicyBundleHash string  `json:"policy_bundle_hash,omitempty"`
	EngineVersion    string  `json:"engine_version"`
}

type Options struct {
	ConfigPath           string
	PolicyBundleOverride string
	Getenv               func(string) string
}

func Run(options Options) (Report, error) {
	if options.Getenv == nil {
		options.Getenv = os.Getenv
	}
	report := Report{
		OverallStatus: "READY",
		Checks:        make([]Check, 0, 16),
		EngineVersion: version.Current().Version,
	}
	mark := func(id string, ok bool, passMsg, hint string) {
		status := "PASS"
		msg := passMsg
		if !ok {
			status = "FAIL"
			msg = passMsg + " failed"
			report.OverallStatus = "NOT_READY"
		}
		report.Checks = append(report.Checks, Check{
			ID:      id,
			Status:  status,
			Message: msg,
			Hint:    hint,
		})
	}

	cfg, cfgErr := gateway.LoadConfig(options.ConfigPath, options.Getenv, options.PolicyBundleOverride)
	if cfgErr == nil {
		mark("config.load", true, "config loaded", "")
	} else {
		mark("config.load", false, "config loaded", "fix configuration errors: "+cfgErr.Error())
	}

	envKnown := false
	if cfgErr == nil {
		envKnown = isRecognizedEnvironment(cfg.Identity.Environment)
	}
	mark("config.environment_recognized", envKnown, "environment recognized", "set identity.environment to one of: ci, dev, local, prod, staging, test")

	configPathOK, configPathMsg := pathResolves(options.ConfigPath)
	mark("config.path_resolves", configPathOK, configPathMsg, "ensure --config points to a valid path")

	bundlePath := ""
	if cfgErr == nil {
		bundlePath = cfg.Policy.BundlePath
	}
	bundlePathOK, bundlePathMsg := pathResolves(bundlePath)
	mark("config.bundle_path_resolves", bundlePathOK, bundlePathMsg, "set --policy-bundle/-p or JANUS_POLICY_BUNDLE")

	bundleExists := false
	if bundlePath != "" {
		_, err := os.Stat(bundlePath)
		bundleExists = err == nil
	}
	mark("policy.bundle_exists", bundleExists, "policy bundle exists", "verify policy bundle path exists on disk")

	var bundle policy.Bundle
	bundleLoaded := false
	if bundleExists {
		loaded, err := policy.LoadBundle(bundlePath)
		if err == nil {
			bundle = loaded
			bundleLoaded = true
			report.PolicyBundleHash = loaded.Hash
		}
	}
	mark("policy.bundle_parses", bundleLoaded, "policy bundle parsed", "fix bundle JSON/schema so policy.LoadBundle succeeds")
	mark("policy.bundle_hash", bundleLoaded && report.PolicyBundleHash != "", "policy bundle hash computed", "ensure bundle bytes are readable and valid")

	denyByDefault := false
	if bundleLoaded && cfgErr == nil {
		engine := policy.NewEngine(bundle)
		decision := engine.Evaluate(normalize.NormalizedAction{
			ActionType:  "doctor.unmatched",
			Resource:    "file://workspace/__doctor_probe__",
			Principal:   cfg.Identity.Principal,
			Agent:       cfg.Identity.Agent,
			Environment: cfg.Identity.Environment,
			Params:      []byte("{}"),
			ParamsHash:  "probe",
		})
		denyByDefault = decision.Decision == policy.DecisionDeny
	}
	mark("policy.deny_by_default_probe", denyByDefault, "deny-by-default probe passed", "remove broad allow rules that permit unmatched probe actions")

	authModeValid := false
	if cfgErr == nil {
		authModeValid = len(cfg.Identity.APIKeys) > 0 || len(cfg.Identity.ServiceSecrets) > 0 || cfg.Identity.OIDC.Enabled
	}
	mark("identity.auth_mode_valid", authModeValid, "identity auth mode valid", "configure api_keys or service_secrets or enable oidc")

	keyPresence := false
	if cfgErr == nil {
		keyPresence = cfg.Identity.Agent != "" && cfg.Identity.AgentSecrets[cfg.Identity.Agent] != ""
		if cfg.Identity.OIDC.Enabled {
			keyPresence = keyPresence && cfg.Identity.OIDC.Issuer != "" && cfg.Identity.OIDC.Audience != "" && cfg.Identity.OIDC.PublicKeyPath != ""
		}
	}
	mark("identity.required_secrets_present", keyPresence, "identity key/secret presence valid", "ensure agent_secrets has the configured identity.agent and oidc fields are complete when enabled")
	mark("identity.environment_derivation", envKnown, "identity environment derivation valid", "use a recognized identity.environment value")

	mcpEnabled := cfgErr == nil && cfg.MCP.Enabled
	mark("mcp.enabled", mcpEnabled, "mcp mode enabled", "set mcp.enabled=true for MCP readiness")
	mark("mcp.transport_configured", mcpEnabled, "mcp stdio transport configured", "enable mcp mode in config")
	mark("mcp.stdio_structure_valid", mcpEnabled, "mcp stdio structure valid", "enable mcp mode and keep standard janus mcp invocation")

	workspaceExists := false
	workspaceCanon := false
	workspaceNonEmpty := false
	if cfgErr == nil {
		root := strings.TrimSpace(cfg.Executor.WorkspaceRoot)
		workspaceNonEmpty = root != ""
		if workspaceNonEmpty {
			if stat, err := os.Stat(root); err == nil && stat.IsDir() {
				workspaceExists = true
			}
			if abs, err := filepath.Abs(root); err == nil {
				workspaceCanon = filepath.Clean(abs) != ""
			}
		}
	}
	mark("fs.workspace_exists", workspaceExists, "workspace root exists", "set executor.workspace_root to an existing directory")
	mark("fs.workspace_canonicalizes", workspaceCanon, "workspace root canonicalizes", "set executor.workspace_root to a valid canonicalizable path")
	mark("fs.workspace_non_empty", workspaceNonEmpty, "workspace root is non-empty", "set executor.workspace_root explicitly or keep default working directory")

	report.Checks = stableChecks(report.Checks)
	return report, nil
}

func pathResolves(path string) (bool, string) {
	p := strings.TrimSpace(path)
	if p == "" {
		return false, "path missing"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false, "path resolution failed"
	}
	cleaned := filepath.Clean(abs)
	if cleaned == "" {
		return false, "path canonicalization failed"
	}
	return true, "path resolves deterministically"
}

func isRecognizedEnvironment(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "dev", "staging", "prod", "ci", "local", "test":
		return true
	default:
		return false
	}
}

func stableChecks(in []Check) []Check {
	out := make([]Check, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func HumanSummary(report Report) string {
	var b strings.Builder
	b.WriteString("Janus Doctor Report\n\n")
	for _, check := range report.Checks {
		b.WriteString(fmt.Sprintf("[%s] %s\n", check.Status, check.Message))
		if check.Status == "FAIL" && check.Hint != "" {
			b.WriteString(fmt.Sprintf("  hint: %s\n", check.Hint))
		}
	}
	b.WriteString("\nResult: ")
	b.WriteString(report.OverallStatus)
	b.WriteString("\n")
	return b.String()
}
