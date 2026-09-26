package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

const toolPinAllowRefundBundle = `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`

func toolPinTestUpstream(dir, mode string) UpstreamServerConfig {
	return UpstreamServerConfig{
		Name:      "retail",
		Transport: "stdio",
		Command:   os.Args[0],
		Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", mode},
		Env:       map[string]string{"GO_WANT_UPSTREAM_MCP_HELPER": "1"},
		Workdir:   dir,
	}
}

func toolPinTestRuntimeOptions(dir, mode string, pins UpstreamToolPinsConfig) RuntimeOptions {
	return RuntimeOptions{
		LogLevel:         "error",
		LogFormat:        "text",
		ErrWriter:        io.Discard,
		UpstreamServers:  []UpstreamServerConfig{toolPinTestUpstream(dir, mode)},
		UpstreamToolPins: pins,
	}
}

func newToolPinTestServer(t *testing.T, dir, bundle, mode string, pins UpstreamToolPinsConfig, recorder audit.Recorder) (*Server, error) {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", toolPinTestRuntimeOptions(dir, mode, pins), recorder)
	if err != nil {
		return nil, err
	}
	server.upstream.setBackoffForTest(0, 0)
	t.Cleanup(func() { _ = server.Close() })
	return server, nil
}

func mustToolPinTestServer(t *testing.T, dir, bundle, mode string, pins UpstreamToolPinsConfig, recorder audit.Recorder) *Server {
	t.Helper()
	server, err := newToolPinTestServer(t, dir, bundle, mode, pins, recorder)
	if err != nil {
		t.Fatalf("new tool pin test server: %v", err)
	}
	return server
}

func expectedHelperRefundHash(t *testing.T, description string) string {
	t.Helper()
	hash, err := ToolDefinitionHash("refund.request", description, helperRefundInputSchema())
	if err != nil {
		t.Fatalf("hash helper definition: %v", err)
	}
	return hash
}

func callRefundForTest(t *testing.T, server *Server, id, orderID string) (Response, action.Response) {
	t.Helper()
	resp := server.handleRequest(Request{
		ID:     id,
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": orderID, "reason": "damaged"}),
	})
	result, _ := resp.Result.(action.Response)
	return resp, result
}

func toolPinAuditEvents(events []audit.Event, classification string) []audit.Event {
	out := make([]audit.Event, 0)
	for _, event := range events {
		if event.EventType == toolPinAuditEventType && event.ResultClassification == classification {
			out = append(out, event)
		}
	}
	return out
}

func readPinnedHashForTest(t *testing.T, path, server, tool string) (string, bool) {
	t.Helper()
	store, err := OpenToolPinStore(path, ToolPinModeRecord)
	if err != nil {
		t.Fatalf("open pin store %s: %v", path, err)
	}
	pin, ok, err := store.Lookup(server, tool)
	if err != nil {
		t.Fatalf("lookup pin: %v", err)
	}
	return pin.DefinitionHash, ok
}

func TestToolPinRecordModePinsFirstCallAndExposesHashesToPolicy(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")
	wantHash := expectedHelperRefundHash(t, helperRefundDescription)
	// The policy only allows the call when both definition hashes are present in the action params.
	bundle := `{"version":"v1","rules":[{"id":"allow-refund-pinned","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"params_match":{"tool_definition_hash":{"equals":"` + wantHash + `"},"tool_definition_pinned_hash":{"equals":"` + wantHash + `"}}}]}`
	recorder := &recordingSink{}
	server := mustToolPinTestServer(t, dir, bundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: pinPath}, recorder)

	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("expected no pin file before the first call, got %v", err)
	}
	resp, result := callRefundForTest(t, server, "first", "ORD-1001")
	if resp.Error != "" || result.Decision != policy.DecisionAllow || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected first call to pin and forward, got %+v", resp)
	}
	if !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("expected forwarded output, got %+v", result)
	}
	pinnedHash, ok := readPinnedHashForTest(t, pinPath, "retail", "refund.request")
	if !ok || pinnedHash != wantHash {
		t.Fatalf("expected pin file to hold %s, got %q ok=%t", wantHash, pinnedHash, ok)
	}

	pinned := toolPinAuditEvents(recorder.snapshot(), toolPinResultPinned)
	if len(pinned) != 1 {
		t.Fatalf("expected exactly one PINNED audit event, got %d", len(pinned))
	}
	event := pinned[0]
	if event.TraceID != "mcp_first" || event.ActionType != "mcp.call" || event.Resource != "mcp://retail/refund.request" || event.Principal != "system" || event.Decision != "" || event.Reason != "" {
		t.Fatalf("unexpected PINNED audit event: %+v", event)
	}
	if event.ExecutorMetadata["tool_definition_hash"] != wantHash || event.ExecutorMetadata["tool_definition_pinned_hash"] != wantHash || event.ExecutorMetadata["tool_pin_mode"] != ToolPinModeRecord || event.ExecutorMetadata["tool_pin_file"] != pinPath || event.ExecutorMetadata["upstream_server"] != "retail" || event.ExecutorMetadata["upstream_tool"] != "refund.request" {
		t.Fatalf("unexpected PINNED audit metadata: %+v", event.ExecutorMetadata)
	}

	resp, result = callRefundForTest(t, server, "second", "ORD-1002")
	if resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("expected second call to match the existing pin, got %+v", resp)
	}
	if got := toolPinAuditEvents(recorder.snapshot(), toolPinResultPinned); len(got) != 1 {
		t.Fatalf("expected no second PINNED event, got %d", len(got))
	}
}

func TestToolPinDeniesChangedDefinitionAfterListChanged(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")
	originalHash := expectedHelperRefundHash(t, helperRefundDescription)
	mutatedHash := expectedHelperRefundHash(t, helperMutatedRefundDescription)
	recorder := &recordingSink{}
	server := mustToolPinTestServer(t, dir, toolPinAllowRefundBundle, "mutating-retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: pinPath}, recorder)

	resp, result := callRefundForTest(t, server, "prime", "ORD-PRIME")
	if resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("prime call: %+v", resp)
	}
	if hash, ok := readPinnedHashForTest(t, pinPath, "retail", "refund.request"); !ok || hash != originalHash {
		t.Fatalf("expected original definition to be pinned, got %q ok=%t", hash, ok)
	}

	refreshed := make(chan string, 4)
	server.upstream.setRefreshHookForTest(func(serverName string) {
		select {
		case refreshed <- serverName:
		default:
		}
	})
	resp, result = callRefundForTest(t, server, "trigger", "LIST_CHANGED")
	if resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("trigger call: %+v", resp)
	}
	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh hook did not fire after tools/list_changed")
	}
	live, ok := server.upstream.toolByName("upstream_retail_refund_request")
	if !ok || live.DefinitionHash != mutatedHash || live.Description != helperMutatedRefundDescription {
		t.Fatalf("expected refreshed registry to carry the mutated definition, got %+v", live)
	}

	resp, result = callRefundForTest(t, server, "after-change", "ORD-2002")
	if resp.Error != "" {
		t.Fatalf("expected a structured deny, got error %+v", resp)
	}
	if result.Decision != policy.DecisionDeny || result.Reason != denyByToolDefinitionChange || result.Output != "" || result.ExecutionMode != "" {
		t.Fatalf("expected deny_by_tool_definition_change before any upstream call, got %+v", result)
	}
	if result.TraceID != "mcp_after-change" || result.ActionID != "mcp_after-change" {
		t.Fatalf("expected deterministic trace/action ids on the deny, got %+v", result)
	}
	if hash, ok := readPinnedHashForTest(t, pinPath, "retail", "refund.request"); !ok || hash != originalHash {
		t.Fatalf("expected the changed definition not to be re-pinned, got %q ok=%t", hash, ok)
	}
	denied := toolPinAuditEvents(recorder.snapshot(), toolPinResultDenied)
	if len(denied) != 1 {
		t.Fatalf("expected one DENIED_TOOL_DEFINITION audit event, got %d", len(denied))
	}
	event := denied[0]
	if event.Decision != policy.DecisionDeny || event.Reason != denyByToolDefinitionChange || event.TraceID != "mcp_after-change" || event.Resource != "mcp://retail/refund.request" {
		t.Fatalf("unexpected deny audit event: %+v", event)
	}
	if event.ExecutorMetadata["tool_definition_hash"] != mutatedHash || event.ExecutorMetadata["tool_definition_pinned_hash"] != originalHash || event.ExecutorMetadata["upstream_server"] != "retail" || event.ExecutorMetadata["upstream_tool"] != "refund.request" {
		t.Fatalf("expected both hashes in the deny audit metadata, got %+v", event.ExecutorMetadata)
	}
	for _, completed := range recorder.snapshot() {
		if completed.EventType == "action.completed" && completed.TraceID == "mcp_after-change" {
			t.Fatalf("expected the denied call not to reach the action pipeline, got %+v", completed)
		}
	}

	// The deny travels through the normal tools/call result shape clients already handle.
	rpc := server.handleRPCRequest(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"rpc-deny"`),
		Method:  "tools/call",
		Params:  mustJSONBytes(map[string]any{"name": "upstream_retail_refund_request", "arguments": map[string]any{"order_id": "ORD-3003", "reason": "damaged"}}),
	}, nil)
	if rpc == nil || rpc.Error != nil {
		t.Fatalf("expected a tools/call result, got %+v", rpc)
	}
	payload, _ := rpc.Result.(map[string]any)
	if isError, _ := payload["isError"].(bool); isError {
		t.Fatalf("expected a governed DENY result rather than a protocol error, got %+v", payload)
	}
	content, _ := payload["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatalf("expected deny content, got %+v", payload)
	}
	if text, _ := content[0]["text"].(string); !strings.Contains(text, "DENY") || !strings.Contains(text, denyByToolDefinitionChange) {
		t.Fatalf("expected DENY text with the reason code, got %q", text)
	}

	// Accepting the new definition through the pin file takes effect without a restart.
	store, err := OpenToolPinStore(pinPath, ToolPinModeRecord)
	if err != nil {
		t.Fatalf("open pin store: %v", err)
	}
	if _, previous, err := store.Pin("retail", "refund.request", mutatedHash, helperMutatedRefundDescription); err != nil || previous == nil || previous.DefinitionHash != originalHash {
		t.Fatalf("accept new definition: previous=%+v err=%v", previous, err)
	}
	resp, result = callRefundForTest(t, server, "accepted", "ORD-4004")
	if resp.Error != "" || result.Decision != policy.DecisionAllow || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected accepted definition to forward again, got %+v", resp)
	}
}

func TestToolPinStrictModeDeniesUnpinnedTool(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")
	recorder := &recordingSink{}
	server := mustToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeStrict, File: pinPath}, recorder)

	resp, result := callRefundForTest(t, server, "unpinned", "ORD-1001")
	if resp.Error != "" {
		t.Fatalf("expected a structured deny, got %+v", resp)
	}
	if result.Decision != policy.DecisionDeny || result.Reason != denyByUnpinnedToolDefinition || result.Output != "" {
		t.Fatalf("expected deny_by_unpinned_tool_definition, got %+v", result)
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("expected strict mode never to create the pin file, got %v", err)
	}
	denied := toolPinAuditEvents(recorder.snapshot(), toolPinResultDenied)
	if len(denied) != 1 || denied[0].Reason != denyByUnpinnedToolDefinition || denied[0].ExecutorMetadata["tool_pin_mode"] != ToolPinModeStrict {
		t.Fatalf("unexpected deny audit events: %+v", denied)
	}
	if _, present := denied[0].ExecutorMetadata["tool_definition_pinned_hash"]; present {
		t.Fatalf("expected no pinned hash for an unpinned tool, got %+v", denied[0].ExecutorMetadata)
	}

	store, err := OpenToolPinStore(pinPath, ToolPinModeStrict)
	if err != nil {
		t.Fatalf("open pin store: %v", err)
	}
	if _, _, err := store.Pin("retail", "refund.request", expectedHelperRefundHash(t, helperRefundDescription), helperRefundDescription); err != nil {
		t.Fatalf("pin definition: %v", err)
	}
	resp, result = callRefundForTest(t, server, "pinned", "ORD-1002")
	if resp.Error != "" || result.Decision != policy.DecisionAllow || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected pinned tool to forward in strict mode, got %+v", resp)
	}
}

func TestToolPinOffModeNeverTouchesFile(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")
	stale := []byte(`{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"` + strings.Repeat("0", 64) + `","pinned_at":"2026-09-01T00:00:00Z","name":"refund.request","description":"stale"}}}` + "\n")
	if err := os.WriteFile(pinPath, stale, 0o600); err != nil {
		t.Fatalf("write stale pin file: %v", err)
	}
	recorder := &recordingSink{}
	server := mustToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeOff, File: pinPath}, recorder)
	if server.upstream.toolPins() != nil {
		t.Fatal("expected no pin store in off mode")
	}
	resp, result := callRefundForTest(t, server, "off", "ORD-1001")
	if resp.Error != "" || result.Decision != policy.DecisionAllow || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected off mode to ignore the stale pin, got %+v", resp)
	}
	data, err := os.ReadFile(pinPath)
	if err != nil || !bytes.Equal(data, stale) {
		t.Fatalf("expected off mode to leave the pin file untouched, err=%v data=%s", err, data)
	}
	for _, event := range recorder.snapshot() {
		if event.EventType == toolPinAuditEventType {
			t.Fatalf("expected no pin audit events in off mode, got %+v", event)
		}
	}

	unsetDir := t.TempDir()
	unset := mustToolPinTestServer(t, unsetDir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{}, nil)
	if resp, result := callRefundForTest(t, unset, "unset", "ORD-1001"); resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("expected unset pins config to behave like off, got %+v", resp)
	}
	entries, err := os.ReadDir(unsetDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "pin") {
			t.Fatalf("expected no pin file to be created, found %s", entry.Name())
		}
	}
}

func TestNewServerFailsClosedOnUnreadablePinFile(t *testing.T) {
	for label, content := range map[string]string{
		"bad hash":      `{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"nothex"}}}`,
		"unknown field": `{"version":"v1","pins":{},"signature":"x"}`,
		"not json":      `pins: []`,
	} {
		dir := t.TempDir()
		pinPath := filepath.Join(dir, "pins.json")
		if err := os.WriteFile(pinPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write pin file: %v", err)
		}
		_, err := newToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: pinPath}, nil)
		if err == nil || !strings.Contains(err.Error(), "parse upstream tool pin file") {
			t.Fatalf("%s: expected startup to fail closed, got %v", label, err)
		}
	}
	dir := t.TempDir()
	_, err := newToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: dir}, nil)
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("expected a directory pin path to fail closed, got %v", err)
	}
	if _, err := newToolPinTestServer(t, t.TempDir(), toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: "trust"}, nil); err == nil || !strings.Contains(err.Error(), "invalid upstream tool pin mode") {
		t.Fatalf("expected unknown mode to fail closed, got %v", err)
	}
}

func TestToolPinRecordModeFailsClosedWhenPinCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "missing-dir", "pins.json")
	recorder := &recordingSink{}
	server := mustToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: pinPath}, recorder)

	resp, _ := callRefundForTest(t, server, "unwritable", "ORD-1001")
	if resp.Error != toolPinStoreError {
		t.Fatalf("expected %s when the pin cannot be written, got %+v", toolPinStoreError, resp)
	}
	failures := toolPinAuditEvents(recorder.snapshot(), toolPinResultStoreError)
	if len(failures) != 1 || failures[0].Decision != policy.DecisionDeny || failures[0].Reason != toolPinStoreError {
		t.Fatalf("expected a TOOL_PIN_STORE_ERROR audit event, got %+v", failures)
	}
	if errText, _ := failures[0].ExecutorMetadata["error"].(string); !strings.Contains(errText, "write upstream tool pin file") {
		t.Fatalf("expected write error in audit metadata, got %+v", failures[0].ExecutorMetadata)
	}
	for _, event := range recorder.snapshot() {
		if event.EventType == "action.completed" && event.TraceID == "mcp_unwritable" {
			t.Fatalf("expected the call not to proceed to the action pipeline, got %+v", event)
		}
	}
}

func TestReloadAppliesToolPinConfig(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")
	bundlePath := filepath.Join(dir, "bundle.json")
	server := mustToolPinTestServer(t, dir, toolPinAllowRefundBundle, "retail", UpstreamToolPinsConfig{}, nil)
	if resp, result := callRefundForTest(t, server, "before", "ORD-1001"); resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("expected call to be allowed before reload, got %+v", resp)
	}

	reload := func(pins UpstreamToolPinsConfig) {
		t.Helper()
		result, err := server.Reload(context.Background(), ReloadOptions{
			BundlePaths:    []string{bundlePath},
			RuntimeOptions: toolPinTestRuntimeOptions(dir, "retail", pins),
			Trigger:        "test",
		})
		if err != nil || result.Outcome != "success" {
			t.Fatalf("reload with %+v: %+v err=%v", pins, result, err)
		}
	}
	reload(UpstreamToolPinsConfig{Mode: ToolPinModeStrict, File: pinPath})
	if resp, result := callRefundForTest(t, server, "strict", "ORD-1002"); resp.Error != "" || result.Decision != policy.DecisionDeny || result.Reason != denyByUnpinnedToolDefinition {
		t.Fatalf("expected strict mode after reload, got %+v", resp)
	}

	// A reload that leaves the pin config unset inherits the current one.
	reload(UpstreamToolPinsConfig{})
	if resp, result := callRefundForTest(t, server, "inherited", "ORD-1003"); resp.Error != "" || result.Decision != policy.DecisionDeny || result.Reason != denyByUnpinnedToolDefinition {
		t.Fatalf("expected inherited strict mode after reload, got %+v", resp)
	}

	reload(UpstreamToolPinsConfig{Mode: ToolPinModeOff})
	if resp, result := callRefundForTest(t, server, "off", "ORD-1004"); resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("expected off mode after reload, got %+v", resp)
	}

	if err := os.WriteFile(pinPath, []byte(`{"version":"v1"`), 0o600); err != nil {
		t.Fatalf("write broken pin file: %v", err)
	}
	result, err := server.Reload(context.Background(), ReloadOptions{
		BundlePaths:    []string{bundlePath},
		RuntimeOptions: toolPinTestRuntimeOptions(dir, "retail", UpstreamToolPinsConfig{Mode: ToolPinModeRecord, File: pinPath}),
		Trigger:        "test",
	})
	if err == nil || result.Outcome != "failure" || !strings.Contains(err.Error(), "parse upstream tool pin file") {
		t.Fatalf("expected reload with a broken pin file to fail closed, got %+v err=%v", result, err)
	}
	if resp, result := callRefundForTest(t, server, "still-off", "ORD-1005"); resp.Error != "" || result.Decision != policy.DecisionAllow {
		t.Fatalf("expected the previous (off) pin config to survive a failed reload, got %+v", resp)
	}
}

func TestEnumerateUpstreamToolDefinitions(t *testing.T) {
	dir := t.TempDir()
	options := toolPinTestRuntimeOptions(dir, "retail", UpstreamToolPinsConfig{})
	definitions, err := EnumerateUpstreamToolDefinitions(options, "retail", identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}, nil)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(definitions) != 1 || definitions[0].Server != "retail" || definitions[0].Tool != "refund.request" || !definitions[0].HasInputSchema {
		t.Fatalf("unexpected definitions: %+v", definitions)
	}
	if definitions[0].DefinitionHash != expectedHelperRefundHash(t, helperRefundDescription) || definitions[0].Description != helperRefundDescription {
		t.Fatalf("unexpected definition hash or description: %+v", definitions[0])
	}
	if _, err := EnumerateUpstreamToolDefinitions(options, "orders", identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}, nil); err == nil || !strings.Contains(err.Error(), "is not configured") {
		t.Fatalf("expected unknown server to fail, got %v", err)
	}
}
