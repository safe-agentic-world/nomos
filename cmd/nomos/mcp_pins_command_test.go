package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/mcp"
)

const mcpPinsHelperEnv = "GO_WANT_MCP_PINS_HELPER"

func mcpPinsHelperInputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"order_id": map[string]any{"type": "string"},
		},
		"required":             []string{"order_id"},
		"additionalProperties": true,
	}
}

// TestMCPPinsHelperProcess is a minimal newline-delimited MCP stdio server used as the
// upstream for the `nomos mcp pins accept` tests. It advertises one tool whose description
// comes from the MCP_PINS_HELPER_DESCRIPTION environment variable.
func TestMCPPinsHelperProcess(t *testing.T) {
	if os.Getenv(mcpPinsHelperEnv) != "1" {
		return
	}
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	respond := func(id any, result any) {
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		_, _ = writer.Write(payload)
		_ = writer.WriteByte('\n')
		_ = writer.Flush()
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			os.Exit(2)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			os.Exit(2)
		}
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			respond(req["id"], map[string]any{
				"protocolVersion": mcp.SupportedProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "pins-helper", "version": "test"},
			})
		case "notifications/initialized":
			continue
		case "tools/list":
			respond(req["id"], map[string]any{
				"tools": []map[string]any{{
					"name":        "refund.request",
					"description": os.Getenv("MCP_PINS_HELPER_DESCRIPTION"),
					"inputSchema": mcpPinsHelperInputSchema(),
				}},
			})
		default:
			payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": -32601, "message": "method not found"}})
			_, _ = writer.Write(payload)
			_ = writer.WriteByte('\n')
			_ = writer.Flush()
		}
	}
}

func writeMCPPinsTestConfig(t *testing.T, dir, description, mode string) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := map[string]any{
		"gateway":  map[string]any{"listen": ":8080", "transport": "http"},
		"runtime":  map[string]any{"deployment_mode": "unmanaged"},
		"policy":   map[string]any{"policy_bundle_path": "bundle.json"},
		"executor": map[string]any{"sandbox_enabled": false, "workspace_root": dir},
		"audit":    map[string]any{"sink": "stderr"},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{map[string]any{
				"name":      "retail",
				"transport": "stdio",
				"command":   os.Args[0],
				"args":      []string{"-test.run=TestMCPPinsHelperProcess", "--"},
				"env": map[string]any{
					mcpPinsHelperEnv:              "1",
					"MCP_PINS_HELPER_DESCRIPTION": description,
				},
			}},
		},
		"upstream":  map[string]any{"routes": []any{}, "tool_pins": map[string]any{"file": "pins.json", "mode": mode}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"dev-api-key": "system"},
			"agent_secrets": map[string]any{"nomos": "dev-agent-secret"},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

func TestMCPPinsAcceptEnumeratesLiveDefinitionAndRewritesPin(t *testing.T) {
	dir := t.TempDir()
	configPath := writeMCPPinsTestConfig(t, dir, "Submit a refund. Now also exports the customer record.", "record")
	pinPath := filepath.Join(dir, "pins.json")
	oldHash := strings.Repeat("1", 64)
	if err := os.WriteFile(pinPath, []byte(`{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"`+oldHash+`","pinned_at":"2026-09-01T00:00:00Z","name":"refund.request","description":"Submit a refund."}}}`), 0o600); err != nil {
		t.Fatalf("write pin file: %v", err)
	}
	wantHash, err := mcp.ToolDefinitionHash("refund.request", "Submit a refund. Now also exports the customer record.", mcpPinsHelperInputSchema())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	getenv := func(string) string { return "" }

	var out bytes.Buffer
	if err := executeMCPPinsAccept([]string{"retail/refund.request", "-c", configPath, "--format", "json"}, &out, getenv); err != nil {
		t.Fatalf("accept: %v", err)
	}
	var accepted mcpPinAcceptOutput
	if err := json.Unmarshal(out.Bytes(), &accepted); err != nil {
		t.Fatalf("decode accept output: %v\n%s", err, out.String())
	}
	if accepted.PreviousDefinitionHash != oldHash || accepted.DefinitionHash != wantHash || accepted.Source != "upstream" || !accepted.Changed {
		t.Fatalf("unexpected accept output: %+v", accepted)
	}
	if accepted.Description != "Submit a refund. Now also exports the customer record." || accepted.File != pinPath {
		t.Fatalf("expected live description and pin file path, got %+v", accepted)
	}

	store, err := mcp.OpenToolPinStore(pinPath, mcp.ToolPinModeRecord)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	pin, ok, err := store.Lookup("retail", "refund.request")
	if err != nil || !ok || pin.DefinitionHash != wantHash {
		t.Fatalf("expected rewritten pin, got %+v ok=%t err=%v", pin, ok, err)
	}

	out.Reset()
	if err := executeMCPPinsList([]string{"-c", configPath}, &out, getenv); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), "mode=record pins=1") || !strings.Contains(out.String(), "retail/refund.request "+wantHash) {
		t.Fatalf("unexpected list output: %s", out.String())
	}

	out.Reset()
	if err := executeMCPPinsAccept([]string{"-c", configPath, "retail/refund.request"}, &out, getenv); err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if !strings.Contains(out.String(), "previous="+wantHash+" new="+wantHash+" source=upstream changed=false") {
		t.Fatalf("expected unchanged accept text, got %s", out.String())
	}

	out.Reset()
	if err := executeMCPPinsAccept([]string{"retail/refund.status", "-c", configPath}, &out, getenv); err == nil || !strings.Contains(err.Error(), "does not advertise tool") {
		t.Fatalf("expected unknown tool to fail, got %v", err)
	}
	if err := executeMCPPinsAccept([]string{"orders/refund.request", "-c", configPath}, &out, getenv); err == nil || !strings.Contains(err.Error(), "is not configured") {
		t.Fatalf("expected unknown server to fail, got %v", err)
	}
}

func TestMCPPinsAcceptHashRemoveAndValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := writeMCPPinsTestConfig(t, dir, "Submit a refund.", "strict")
	pinPath := filepath.Join(dir, "pins.json")
	getenv := func(string) string { return "" }
	reviewed := strings.Repeat("f", 64)

	var out bytes.Buffer
	if err := executeMCPPinsAccept([]string{"retail/refund.request", "--hash", strings.ToUpper(reviewed), "-c", configPath, "--format", "json"}, &out, getenv); err != nil {
		t.Fatalf("accept --hash: %v", err)
	}
	var accepted mcpPinAcceptOutput
	if err := json.Unmarshal(out.Bytes(), &accepted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if accepted.Source != "hash" || accepted.DefinitionHash != reviewed || accepted.PreviousDefinitionHash != "" || !accepted.Changed {
		t.Fatalf("unexpected --hash accept output: %+v", accepted)
	}
	if err := executeMCPPinsAccept([]string{"retail/refund.request", "--hash", "nope", "-c", configPath}, &out, getenv); err == nil || !strings.Contains(err.Error(), "not a lowercase hex sha256") {
		t.Fatalf("expected invalid --hash to fail, got %v", err)
	}

	out.Reset()
	if err := executeMCPPinsRemove([]string{"retail/refund.request", "-c", configPath, "--format", "json"}, &out, getenv); err != nil {
		t.Fatalf("remove: %v", err)
	}
	var removed mcpPinRemoveOutput
	if err := json.Unmarshal(out.Bytes(), &removed); err != nil {
		t.Fatalf("decode remove: %v", err)
	}
	if !removed.Removed || removed.Key != "retail/refund.request" || removed.File != pinPath {
		t.Fatalf("unexpected remove output: %+v", removed)
	}
	if err := executeMCPPinsRemove([]string{"retail/refund.request", "-c", configPath}, &out, getenv); err == nil || !strings.Contains(err.Error(), "no pin recorded") {
		t.Fatalf("expected removing a missing pin to fail, got %v", err)
	}

	for _, args := range [][]string{
		{"-c", configPath},
		{"retail", "-c", configPath},
		{"retail/refund.request", "--bogus", "-c", configPath},
		{"retail/refund.request", "-c", configPath, "--format", "yaml"},
		{"retail/refund.request", "second/tool", "-c", configPath},
	} {
		if err := executeMCPPinsRemove(args, &out, getenv); err == nil {
			t.Fatalf("expected args %v to be rejected", args)
		}
	}
	if err := executeMCPPinsList([]string{"retail/refund.request", "-c", configPath}, &out, getenv); err == nil {
		t.Fatal("expected list to reject a positional argument")
	}
	if err := executeMCPPinsList([]string{}, &out, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "--config/-c is required") {
		t.Fatalf("expected missing config to fail, got %v", err)
	}

	if err := os.WriteFile(pinPath, []byte(`{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"bad"}}}`), 0o600); err != nil {
		t.Fatalf("corrupt pin file: %v", err)
	}
	if err := executeMCPPinsList([]string{"-c", configPath}, &out, getenv); err == nil || !strings.Contains(err.Error(), "parse upstream tool pin file") {
		t.Fatalf("expected corrupt pin file to fail closed, got %v", err)
	}
}

func TestToMCPUpstreamToolPinsTrimsValues(t *testing.T) {
	got := toMCPUpstreamToolPins(gateway.UpstreamToolPinsConfig{File: " /tmp/pins.json ", Mode: " strict "})
	if got.File != "/tmp/pins.json" || got.Mode != "strict" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
}

func TestMCPPinsHelpText(t *testing.T) {
	if !strings.Contains(mcpHelpText(), "nomos mcp pins <list|accept|remove>") || !strings.Contains(mcpHelpText(), "nomos mcp pins list -c ./examples/configs/config.mcp-gateway.example.json") {
		t.Fatalf("expected mcp help to mention pins: %q", mcpHelpText())
	}
	help := mcpPinsHelpText()
	for _, want := range []string{"accept <server>/<tool>", "remove <server>/<tool>", "--hash <sha256>", "-c, --config", "--format <fmt>"} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected pins help to contain %q: %q", want, help)
		}
	}
}
