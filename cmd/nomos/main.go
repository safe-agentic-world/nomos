package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/doctor"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/mcp"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/version"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		info := version.Current()
		fmt.Println(info.String())
	case "serve":
		runServe(os.Args[2:])
	case "mcp":
		runMCP(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "doctor":
		os.Exit(runDoctorCommand(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	default:
		usage()
		os.Exit(2)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	var policyBundle string
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.Usage = func() { _, _ = io.WriteString(fs.Output(), serveHelpText()) }
	fs.Parse(args)

	resolved, err := resolveServeInvocation(configPath, policyBundle, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := gateway.LoadConfig(resolved.ConfigPath, os.Getenv, resolved.PolicyBundle)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	log.Printf("nomos gateway listening on %s (%s)", cfg.Gateway.Listen, cfg.Gateway.Transport)
	if err := gw.Start(); err != nil {
		log.Fatalf("gateway start: %v", err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gw.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("gateway shutdown: %v", err)
	}
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	var policyBundle string
	var logLevel string
	var logFormat string
	var quiet bool
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.StringVar(&logLevel, "log-level", "info", "mcp log level: error|warn|info|debug")
	fs.StringVar(&logLevel, "l", "info", "mcp log level: error|warn|info|debug")
	fs.BoolVar(&quiet, "quiet", false, "suppress startup banner and non-error logs")
	fs.BoolVar(&quiet, "q", false, "suppress startup banner and non-error logs")
	fs.StringVar(&logFormat, "log-format", "text", "mcp log format: text|json")
	fs.Usage = func() { _, _ = io.WriteString(fs.Output(), mcpHelpText()) }
	fs.Parse(args)

	resolved, err := resolveMCPInvocation(configPath, policyBundle, logLevel, quiet, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	runtimeOptions, err := mcp.ParseRuntimeOptions(mcp.RuntimeOptions{
		LogLevel:  resolved.LogLevel,
		Quiet:     resolved.Quiet,
		LogFormat: logFormat,
		ErrWriter: os.Stderr,
	})
	if err != nil {
		log.Fatalf("invalid mcp runtime options: %v", err)
	}
	cfg, err := gateway.LoadConfig(resolved.ConfigPath, os.Getenv, resolved.PolicyBundle)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if strings.EqualFold(resolved.LogLevelSource, "env") && strings.EqualFold(resolved.LogLevel, "debug") {
		log.Printf("mcp log-level resolved from env NOMOS_LOG_LEVEL")
	}
	id := identity.VerifiedIdentity{
		Principal:   cfg.Identity.Principal,
		Agent:       cfg.Identity.Agent,
		Environment: cfg.Identity.Environment,
	}
	if err := mcp.RunStdioWithRuntimeOptions(cfg.Policy.BundlePath, id, cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines, cfg.Approvals.Enabled, cfg.Executor.SandboxEnabled, cfg.Executor.SandboxProfile, runtimeOptions); err != nil {
		log.Fatalf("mcp server error: %v", err)
	}
}

func runPolicy(args []string) {
	if len(args) == 0 {
		log.Fatal("policy command required: test|explain")
	}
	switch args[0] {
	case "test":
		runPolicyTest(args[1:])
	case "explain":
		runPolicyExplain(args[1:])
	default:
		log.Fatal("policy command required: test|explain")
	}
}

func runPolicyTest(args []string) {
	actionPath, bundlePath := parsePolicyFlags("test", args)
	actionData, err := os.ReadFile(actionPath)
	if err != nil {
		log.Fatalf("read action: %v", err)
	}
	act, err := action.DecodeAction(actionData)
	if err != nil {
		log.Fatalf("decode action: %v", err)
	}
	bundle, err := policy.LoadBundle(bundlePath)
	if err != nil {
		log.Fatalf("load bundle: %v", err)
	}
	engine := policy.NewEngine(bundle)
	normalized, err := normalize.Action(act)
	if err != nil {
		log.Fatalf("normalize action: %v", err)
	}
	decision := engine.Evaluate(normalized)
	payload := map[string]any{
		"decision":           decision.Decision,
		"reason_code":        decision.ReasonCode,
		"matched_rule_ids":   decision.MatchedRuleIDs,
		"policy_bundle_hash": decision.PolicyBundleHash,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(payload)
}

func runPolicyExplain(args []string) {
	actionPath, bundlePath, configPath := parsePolicyExplainFlags(args)
	actionData, err := os.ReadFile(actionPath)
	if err != nil {
		log.Fatalf("read action: %v", err)
	}
	act, err := action.DecodeAction(actionData)
	if err != nil {
		log.Fatalf("decode action: %v", err)
	}
	bundle, err := policy.LoadBundle(bundlePath)
	if err != nil {
		log.Fatalf("load bundle: %v", err)
	}
	engine := policy.NewEngine(bundle)
	normalized, err := normalize.Action(act)
	if err != nil {
		log.Fatalf("normalize action: %v", err)
	}
	explanation := engine.Explain(normalized)
	settings, err := deriveExplainSettings(configPath, bundlePath, os.Getenv)
	if err != nil {
		log.Fatalf("derive explain settings: %v", err)
	}
	payload := buildPolicyExplainPayload(explanation, normalized, settings)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

type explainSettings struct {
	AssuranceLevel     string
	SuggestRemediation bool
}

func buildPolicyExplainPayload(explanation policy.ExplainDetails, normalized normalize.NormalizedAction, settings explainSettings) map[string]any {
	payload := map[string]any{
		"decision":            explanation.Decision.Decision,
		"reason_code":         explanation.Decision.ReasonCode,
		"matched_rule_ids":    explanation.Decision.MatchedRuleIDs,
		"policy_bundle_hash":  explanation.Decision.PolicyBundleHash,
		"engine_version":      version.Current().Version,
		"assurance_level":     settings.AssuranceLevel,
		"obligations_preview": explanation.ObligationsPreview,
	}
	if explanation.Decision.Decision != policy.DecisionAllow {
		whyDenied := map[string]any{
			"reason_code":        explanation.Decision.ReasonCode,
			"deny_rules":         buildDeniedRulePayload(explanation.DenyRules),
			"matched_conditions": buildOverallMatchedConditions(explanation),
			"remediation_hint":   remediationHint(explanation, normalized),
		}
		payload["why_denied"] = whyDenied
		if settings.SuggestRemediation {
			payload["minimal_allowing_change"] = remediationSuggestion(explanation, normalized)
		}
	}
	return payload
}

func parsePolicyExplainFlags(args []string) (string, string, string) {
	fs := flag.NewFlagSet("policy explain", flag.ExitOnError)
	actionPath := fs.String("action", "", "path to action json")
	bundlePath := fs.String("bundle", "", "path to policy bundle")
	configPath := fs.String("config", "", "path to config json")
	fs.Parse(args)
	if *actionPath == "" || *bundlePath == "" {
		log.Fatal("both --action and --bundle are required")
	}
	return *actionPath, *bundlePath, *configPath
}

func deriveExplainSettings(configPath, bundlePath string, getenv func(string) string) (explainSettings, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if strings.TrimSpace(configPath) != "" {
		cfg, err := gateway.LoadConfig(configPath, getenv, bundlePath)
		if err != nil {
			return explainSettings{}, err
		}
		return explainSettings{
			AssuranceLevel:     assurance.Derive(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee),
			SuggestRemediation: cfg.Policy.ExplainSuggestions == nil || *cfg.Policy.ExplainSuggestions,
		}, nil
	}
	deploymentMode := strings.TrimSpace(getenv("NOMOS_RUNTIME_DEPLOYMENT_MODE"))
	if deploymentMode == "" {
		deploymentMode = "unmanaged"
	}
	suggestRemediation := true
	if value := strings.TrimSpace(getenv("NOMOS_POLICY_EXPLAIN_SUGGESTIONS")); value != "" {
		suggestRemediation = parseBoolEnv(value)
	}
	return explainSettings{
		AssuranceLevel:     assurance.Derive(deploymentMode, parseBoolEnv(getenv("NOMOS_RUNTIME_STRONG_GUARANTEE"))),
		SuggestRemediation: suggestRemediation,
	}, nil
}

func deriveExplainAssurance(configPath, bundlePath string, getenv func(string) string) (string, error) {
	settings, err := deriveExplainSettings(configPath, bundlePath, getenv)
	if err != nil {
		return "", err
	}
	return settings.AssuranceLevel, nil
}

func buildDeniedRulePayload(rules []policy.DeniedRuleExplanation) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"rule_id":            rule.RuleID,
			"reason_code":        rule.ReasonCode,
			"matched_conditions": rule.MatchedConditions,
		})
	}
	return out
}

func buildOverallMatchedConditions(explanation policy.ExplainDetails) map[string]bool {
	if len(explanation.DenyRules) > 0 {
		return map[string]bool{
			"deny_rule_match": true,
		}
	}
	if len(explanation.RequireApprovalRuleIDs) > 0 {
		return map[string]bool{
			"approval_rule_match": true,
		}
	}
	return map[string]bool{
		"matching_allow_rule": false,
	}
}

func remediationHint(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch explanation.Decision.ReasonCode {
	case "require_approval_by_rule":
		return "This action requires approval before it can proceed."
	case "deny_by_rule":
		return "A deny rule matched this action."
	default:
		switch normalized.ActionType {
		case "net.http_request":
			return "This network destination is not currently allowed."
		case "process.exec":
			return "This command is not currently allowed."
		case "fs.write", "repo.apply_patch":
			return "This write target is not currently allowed."
		default:
			return "No matching allow rule was found for this action."
		}
	}
}

func remediationSuggestion(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch normalized.ActionType {
	case "net.http_request":
		host := hostFromNormalizedResource(normalized.Resource)
		if host != "" {
			return "This host is not currently allowed; use an allowlisted host, request approval, or update the network allowlist for " + host + "."
		}
		return "This host is not currently allowed; use an allowlisted host or request approval."
	case "process.exec":
		return "Exec is restricted; use an allowlisted command or request approval."
	case "fs.write", "repo.apply_patch":
		return "Write access is restricted for this resource; use an allowed path or request approval."
	default:
		if explanation.Decision.ReasonCode == "require_approval_by_rule" {
			return "Request approval for this action."
		}
		return "Adjust the requested action to match an allowlisted resource or request approval."
	}
}

func hostFromNormalizedResource(resource string) string {
	if !strings.HasPrefix(resource, "url://") {
		return ""
	}
	trimmed := strings.TrimPrefix(resource, "url://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func parseBoolEnv(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return err == nil && parsed
}

func parsePolicyFlags(name string, args []string) (string, string) {
	fs := flag.NewFlagSet("policy "+name, flag.ExitOnError)
	actionPath := fs.String("action", "", "path to action json")
	bundlePath := fs.String("bundle", "", "path to policy bundle")
	fs.Parse(args)
	if *actionPath == "" || *bundlePath == "" {
		log.Fatal("both --action and --bundle are required")
	}
	return *actionPath, *bundlePath
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func usage() {
	_, _ = io.WriteString(os.Stderr, rootHelpText())
}

func runDoctorCommand(args []string, stdout io.Writer, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	var policyBundle string
	var format string
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.StringVar(&format, "format", "text", "doctor output format: text|json")
	fs.Usage = func() { _, _ = io.WriteString(fs.Output(), doctorHelpText()) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	configResolved, _, err := resolvePathOption(configPath, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		writeRedactedLine(stderr, err.Error())
		return 1
	}
	bundleResolved, _, err := resolvePathOption(policyBundle, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		writeRedactedLine(stderr, err.Error())
		return 1
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "text" && format != "json" {
		writeRedactedLine(stderr, "invalid --format: use text or json")
		return 2
	}
	report, err := doctor.Run(doctor.Options{
		ConfigPath:           configResolved,
		PolicyBundleOverride: bundleResolved,
		Getenv:               getenv,
	})
	if err != nil {
		writeRedactedLine(stderr, "doctor internal error: "+err.Error())
		return 2
	}
	if format == "json" {
		data, err := json.Marshal(report)
		if err != nil {
			writeRedactedLine(stderr, "doctor internal error: "+err.Error())
			return 2
		}
		writeRedactedLine(stdout, string(data))
	} else {
		writeRedactedLine(stdout, doctor.HumanSummary(report))
	}
	if report.OverallStatus == "READY" {
		return 0
	}
	return 1
}

type resolvedServeInvocation struct {
	ConfigPath   string
	PolicyBundle string
}

type resolvedMCPInvocation struct {
	ConfigPath     string
	PolicyBundle   string
	LogLevel       string
	LogLevelSource string
	Quiet          bool
}

func resolveServeInvocation(configFlag, policyFlag string, getenv func(string) string) (resolvedServeInvocation, error) {
	configRaw, _, err := resolvePathOption(configFlag, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		return resolvedServeInvocation{}, err
	}
	bundleRaw, _, err := resolvePathOption(policyFlag, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		return resolvedServeInvocation{}, err
	}
	return resolvedServeInvocation{
		ConfigPath:   configRaw,
		PolicyBundle: bundleRaw,
	}, nil
}

func resolveMCPInvocation(configFlag, policyFlag, logLevelFlag string, quiet bool, getenv func(string) string) (resolvedMCPInvocation, error) {
	configRaw, _, err := resolvePathOption(configFlag, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		return resolvedMCPInvocation{}, err
	}
	bundleRaw, _, err := resolvePathOption(policyFlag, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		return resolvedMCPInvocation{}, err
	}
	level, source := resolveValue(logLevelFlag, getenv("NOMOS_LOG_LEVEL"))
	if level == "" {
		level = "info"
		source = "default"
	}
	return resolvedMCPInvocation{
		ConfigPath:     configRaw,
		PolicyBundle:   bundleRaw,
		LogLevel:       level,
		LogLevelSource: source,
		Quiet:          quiet,
	}, nil
}

func resolvePathOption(flagValue, envValue, flagName, envName string, required bool) (string, string, error) {
	value, source := resolveValue(flagValue, envValue)
	if value == "" {
		if required {
			return "", "", fmt.Errorf("%s is required (or %s)", flagName, envName)
		}
		return "", "", nil
	}
	resolved, err := resolveAbsolutePath(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid path for %s/%s: %w", flagName, envName, err)
	}
	return resolved, source, nil
}

func resolveValue(flagValue, envValue string) (string, string) {
	trimmedFlag := strings.TrimSpace(flagValue)
	if trimmedFlag != "" {
		return trimmedFlag, "flag"
	}
	trimmedEnv := strings.TrimSpace(envValue)
	if trimmedEnv != "" {
		return trimmedEnv, "env"
	}
	return "", ""
}

func resolveAbsolutePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func rootHelpText() string {
	return "nomos commands:\n" +
		"  version    print build metadata\n" +
		"  serve      start gateway server\n" +
		"  mcp        start MCP stdio server\n" +
		"  policy     policy test/explain\n" +
		"  doctor     deterministic preflight checks\n\n" +
		"example:\n" +
		"  nomos mcp -c config.example.json -p policies/m1_5_minimal.json\n"
}

func serveHelpText() string {
	return "usage: nomos serve [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n\n" +
		"example:\n" +
		"  nomos serve -c config.example.json -p policies/m1_5_minimal.json\n"
}

func mcpHelpText() string {
	return "usage: nomos mcp [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n" +
		"  -l, --log-level <level>      error|warn|info|debug (or NOMOS_LOG_LEVEL)\n" +
		"  -q, --quiet                  suppress banner and non-error logs\n" +
		"      --log-format <format>    text|json\n\n" +
		"example:\n" +
		"  nomos mcp -c config.example.json -p policies/m1_5_minimal.json\n"
}

func doctorHelpText() string {
	return "usage: nomos doctor [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n" +
		"      --format <format>        text|json\n\n" +
		"example:\n" +
		"  nomos doctor -c config.example.json --format json\n"
}

func writeRedactedLine(w io.Writer, value string) {
	redacted := redact.DefaultRedactor().RedactText(value)
	if !strings.HasSuffix(redacted, "\n") {
		redacted += "\n"
	}
	_, _ = io.WriteString(w, redacted)
}
