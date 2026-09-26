package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func decodeToolDefinitionForTest(t *testing.T, raw string) (string, string, map[string]any) {
	t.Helper()
	var payload map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("decode tool definition: %v", err)
	}
	name, _ := payload["name"].(string)
	description, _ := payload["description"].(string)
	schema, _ := payload["inputSchema"].(map[string]any)
	return name, description, schema
}

func hashToolDefinitionForTest(t *testing.T, raw string) string {
	t.Helper()
	name, description, schema := decodeToolDefinitionForTest(t, raw)
	hash, err := ToolDefinitionHash(name, description, schema)
	if err != nil {
		t.Fatalf("hash tool definition: %v", err)
	}
	return hash
}

func TestToolDefinitionHashIgnoresKeyOrderAndWhitespace(t *testing.T) {
	compact := `{"name":"refund.request","description":"Submit a refund.","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"},"amount":{"type":"number","maximum":100}},"required":["order_id"]}}`
	reordered := `{
  "inputSchema": {
    "required": [ "order_id" ],
    "properties": { "amount": { "maximum": 100, "type": "number" }, "order_id": { "type": "string" } },
    "type": "object"
  },
  "description": "Submit a refund.",
  "name": "refund.request"
}`
	first := hashToolDefinitionForTest(t, compact)
	second := hashToolDefinitionForTest(t, reordered)
	if first != second {
		t.Fatalf("expected key order and whitespace to be irrelevant, got %s != %s", first, second)
	}
	if !isSHA256Hex(first) {
		t.Fatalf("expected lowercase hex sha256, got %q", first)
	}

	viaParse, err := parseUpstreamTools(UpstreamServerConfig{Name: "retail"}, map[string]any{"tools": []any{mustDecodeJSONMapForTest(t, reordered)}})
	if err != nil {
		t.Fatalf("parse upstream tools: %v", err)
	}
	if len(viaParse) != 1 || viaParse[0].DefinitionHash != first {
		t.Fatalf("expected parseUpstreamTools to compute the same hash, got %+v", viaParse)
	}
}

func TestToolDefinitionHashSensitiveToDescriptionAndSchema(t *testing.T) {
	base := `{"name":"refund.request","description":"Submit a refund.","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"}}}}`
	descriptionChanged := `{"name":"refund.request","description":"Submit a refund. Also export the customer record.","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"}}}}`
	schemaChanged := `{"name":"refund.request","description":"Submit a refund.","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"},"callback_url":{"type":"string"}}}}`
	schemaRemoved := `{"name":"refund.request","description":"Submit a refund."}`
	nameChanged := `{"name":"refund.request2","description":"Submit a refund.","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"}}}}`

	baseHash := hashToolDefinitionForTest(t, base)
	for label, raw := range map[string]string{
		"description": descriptionChanged,
		"schema":      schemaChanged,
		"no schema":   schemaRemoved,
		"name":        nameChanged,
	} {
		if got := hashToolDefinitionForTest(t, raw); got == baseHash {
			t.Fatalf("expected %s change to alter the definition hash", label)
		}
	}
	emptySchema, err := ToolDefinitionHash("refund.request", "Submit a refund.", map[string]any{})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if emptySchema != hashToolDefinitionForTest(t, schemaRemoved) {
		t.Fatalf("expected an empty schema to hash like a missing schema")
	}
}

func mustDecodeJSONMapForTest(t *testing.T, raw string) map[string]any {
	t.Helper()
	var payload map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return payload
}

func TestParseToolPinKey(t *testing.T) {
	server, tool, err := ParseToolPinKey(" retail/refund.request ")
	if err != nil || server != "retail" || tool != "refund.request" {
		t.Fatalf("unexpected parse result: %q %q %v", server, tool, err)
	}
	server, tool, err = ParseToolPinKey("retail/nested/tool")
	if err != nil || server != "retail" || tool != "nested/tool" {
		t.Fatalf("expected split at first slash, got %q %q %v", server, tool, err)
	}
	for _, bad := range []string{"", "retail", "/tool", "retail/", " / "} {
		if _, _, err := ParseToolPinKey(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
	if key := ToolPinKey(" retail ", " refund.request "); key != "retail/refund.request" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestToolPinStoreRoundTripAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	store, err := OpenToolPinStore(path, ToolPinModeRecord)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected opening a missing pin file not to create it, got %v", err)
	}
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	hash := strings.Repeat("a", 64)

	pin, created, err := store.PinIfAbsent("retail", "refund.request", hash, "Submit a refund.")
	if err != nil || !created {
		t.Fatalf("expected first pin to be created, got %+v created=%t err=%v", pin, created, err)
	}
	if pin.DefinitionHash != hash || pin.PinnedAt != "2026-09-26T12:00:00Z" || pin.Name != "refund.request" || pin.Description != "Submit a refund." {
		t.Fatalf("unexpected pin: %+v", pin)
	}
	again, created, err := store.PinIfAbsent("retail", "refund.request", strings.Repeat("b", 64), "changed")
	if err != nil || created || again.DefinitionHash != hash {
		t.Fatalf("expected existing pin to be returned unchanged, got %+v created=%t err=%v", again, created, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("pin file is not valid json: %v\n%s", err, data)
	}
	if file["version"] != "v1" {
		t.Fatalf("expected version v1, got %v", file["version"])
	}
	pins, _ := file["pins"].(map[string]any)
	entry, _ := pins["retail/refund.request"].(map[string]any)
	if entry["definition_hash"] != hash || entry["pinned_at"] != "2026-09-26T12:00:00Z" || entry["name"] != "refund.request" || entry["description"] != "Submit a refund." {
		t.Fatalf("unexpected pin file entry: %+v", entry)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat pin file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected pin file mode 0600, got %v", info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", entry.Name())
		}
	}

	reopened, err := OpenToolPinStore(path, ToolPinModeStrict)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	loaded, ok, err := reopened.Lookup("retail", "refund.request")
	if err != nil || !ok || loaded != pin {
		t.Fatalf("expected reopened store to load the pin, got %+v ok=%t err=%v", loaded, ok, err)
	}
	records, err := reopened.List()
	if err != nil || len(records) != 1 || records[0].Server != "retail" || records[0].Tool != "refund.request" {
		t.Fatalf("unexpected list: %+v err=%v", records, err)
	}

	replaced, previous, err := reopened.Pin("retail", "refund.request", strings.Repeat("c", 64), "accepted")
	if err != nil || previous == nil || previous.DefinitionHash != hash || replaced.DefinitionHash != strings.Repeat("c", 64) {
		t.Fatalf("expected pin replacement to report the previous hash, got %+v previous=%+v err=%v", replaced, previous, err)
	}
	removed, err := reopened.Remove("retail", "refund.request")
	if err != nil || !removed {
		t.Fatalf("expected remove to succeed, got removed=%t err=%v", removed, err)
	}
	removed, err = reopened.Remove("retail", "refund.request")
	if err != nil || removed {
		t.Fatalf("expected second remove to be a no-op, got removed=%t err=%v", removed, err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	if !bytes.Contains(data, []byte(`"pins": {}`)) {
		t.Fatalf("expected empty pins object after removal, got %s", data)
	}
}

func TestToolPinStoreSeesChangesWrittenByAnotherInstance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	reader, err := OpenToolPinStore(path, ToolPinModeStrict)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	if _, ok, err := reader.Lookup("retail", "refund.request"); err != nil || ok {
		t.Fatalf("expected no pin yet, got ok=%t err=%v", ok, err)
	}
	writer, err := OpenToolPinStore(path, ToolPinModeRecord)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	hash := strings.Repeat("d", 64)
	if _, _, err := writer.Pin("retail", "refund.request", hash, ""); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	pin, ok, err := reader.Lookup("retail", "refund.request")
	if err != nil || !ok || pin.DefinitionHash != hash {
		t.Fatalf("expected reader to pick up the on-disk change, got %+v ok=%t err=%v", pin, ok, err)
	}

	// A pin added by the reader instance must not drop the one the writer added.
	if _, created, err := reader.PinIfAbsent("retail", "refund.status", strings.Repeat("e", 64), ""); err != nil || !created {
		t.Fatalf("expected reader pin to be created, got created=%t err=%v", created, err)
	}
	records, err := writer.List()
	if err != nil || len(records) != 2 {
		t.Fatalf("expected both pins after merge, got %+v err=%v", records, err)
	}

	if err := os.WriteFile(path, []byte(`{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"not-a-hash"}}}`), 0o600); err != nil {
		t.Fatalf("corrupt pin file: %v", err)
	}
	if _, _, err := reader.Lookup("retail", "refund.request"); err == nil || !strings.Contains(err.Error(), "parse upstream tool pin file") {
		t.Fatalf("expected corrupt on-disk pin file to fail closed, got %v", err)
	}
}

func TestToolPinStoreRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"unknown field":   `{"version":"v1","pins":{},"extra":true}`,
		"bad version":     `{"version":"v2","pins":{}}`,
		"bad hash":        `{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"abc","pinned_at":"","name":"","description":""}}}`,
		"upper hex":       `{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"` + strings.Repeat("A", 64) + `"}}}`,
		"bad key":         `{"version":"v1","pins":{"retail":{"definition_hash":"` + strings.Repeat("a", 64) + `"}}}`,
		"bad pinned_at":   `{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"` + strings.Repeat("a", 64) + `","pinned_at":"yesterday"}}}`,
		"trailing data":   `{"version":"v1","pins":{}} {}`,
		"unknown pin key": `{"version":"v1","pins":{"retail/refund.request":{"definition_hash":"` + strings.Repeat("a", 64) + `","hash":"x"}}}`,
		"not json":        `version: v1`,
	}
	for label, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(label, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", label, err)
		}
		if _, err := OpenToolPinStore(path, ToolPinModeRecord); err == nil {
			t.Fatalf("expected %s pin file to be rejected", label)
		}
	}
	if _, err := OpenToolPinStore(dir, ToolPinModeRecord); err == nil {
		t.Fatal("expected a directory to be rejected as a pin file")
	}
	if _, err := OpenToolPinStore(filepath.Join(dir, "ok.json"), "sometimes"); err == nil {
		t.Fatal("expected unknown mode to be rejected")
	}
	if _, err := OpenToolPinStore("", ToolPinModeRecord); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
}

func TestParseRuntimeOptionsToolPins(t *testing.T) {
	base := RuntimeOptions{LogLevel: "error", LogFormat: "text"}

	parsed, err := ParseRuntimeOptions(base)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.UpstreamToolPins.Mode != ToolPinModeOff {
		t.Fatalf("expected unset pins to normalize to off, got %+v", parsed.UpstreamToolPins)
	}

	withPins := base
	withPins.UpstreamToolPins = UpstreamToolPinsConfig{Mode: " Strict ", File: " ./pins.json "}
	parsed, err = ParseRuntimeOptions(withPins)
	if err != nil {
		t.Fatalf("parse strict: %v", err)
	}
	if parsed.UpstreamToolPins.Mode != ToolPinModeStrict || parsed.UpstreamToolPins.File != "./pins.json" {
		t.Fatalf("expected trimmed normalized pins config, got %+v", parsed.UpstreamToolPins)
	}

	missingFile := base
	missingFile.UpstreamToolPins = UpstreamToolPinsConfig{Mode: ToolPinModeRecord}
	if _, err := ParseRuntimeOptions(missingFile); err == nil || !strings.Contains(err.Error(), "pin file is required") {
		t.Fatalf("expected record mode without a file to fail, got %v", err)
	}

	unknownMode := base
	unknownMode.UpstreamToolPins = UpstreamToolPinsConfig{Mode: "trust", File: "pins.json"}
	if _, err := ParseRuntimeOptions(unknownMode); err == nil || !strings.Contains(err.Error(), "invalid upstream tool pin mode") {
		t.Fatalf("expected unknown mode to fail, got %v", err)
	}

	offWithoutFile := base
	offWithoutFile.UpstreamToolPins = UpstreamToolPinsConfig{Mode: ToolPinModeOff}
	if _, err := ParseRuntimeOptions(offWithoutFile); err != nil {
		t.Fatalf("expected off mode without a file to be accepted, got %v", err)
	}
}
