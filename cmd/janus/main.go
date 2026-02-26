package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ai-developer-project/janus/internal/action"
	"github.com/ai-developer-project/janus/internal/gateway"
	"github.com/ai-developer-project/janus/internal/identity"
	"github.com/ai-developer-project/janus/internal/mcp"
	"github.com/ai-developer-project/janus/internal/normalize"
	"github.com/ai-developer-project/janus/internal/policy"
	"github.com/ai-developer-project/janus/internal/version"
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
	default:
		usage()
		os.Exit(2)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config json")
	policyBundle := fs.String("policy-bundle", "", "path to policy bundle")
	fs.Parse(args)

	if *configPath == "" {
		log.Fatal("config path is required")
	}

	cfg, err := gateway.LoadConfig(*configPath, os.Getenv, *policyBundle)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	log.Printf("janus gateway listening on %s (%s)", cfg.Gateway.Listen, cfg.Gateway.Transport)
	if err := gw.Start(); err != nil {
		log.Fatalf("gateway start: %v", err)
	}
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config json")
	policyBundle := fs.String("policy-bundle", "", "path to policy bundle")
	fs.Parse(args)

	if *configPath == "" {
		log.Fatal("config path is required")
	}
	cfg, err := gateway.LoadConfig(*configPath, os.Getenv, *policyBundle)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	id := identity.VerifiedIdentity{
		Principal:   cfg.Identity.Principal,
		Agent:       cfg.Identity.Agent,
		Environment: cfg.Identity.Environment,
	}
	if err := mcp.RunStdio(cfg.Policy.BundlePath, id, cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines, cfg.Approvals.Enabled, cfg.Executor.SandboxEnabled, cfg.Executor.SandboxProfile); err != nil {
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
	actionPath, bundlePath := parsePolicyFlags("explain", args)
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
		"engine_version":     version.Current().Version,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
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
	message := map[string]string{
		"version": "print build metadata",
		"serve":   "start gateway server",
		"mcp":     "start MCP stdio server",
		"policy":  "policy test/explain",
	}
	_ = json.NewEncoder(os.Stderr).Encode(message)
}
