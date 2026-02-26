package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ai-developer-project/janus/internal/identity"
	"github.com/ai-developer-project/janus/internal/service"
)

func TestCapabilitiesDifferByIdentity(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["janus"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	resp := server.handleCapabilities(Request{ID: "1", Method: "janus.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	found := false
	for _, tool := range tools.EnabledTools {
		if tool == "janus.fs_read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected fs_read to be enabled")
	}

	serverOther, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "other",
		Agent:       "janus",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server other: %v", err)
	}
	respOther := serverOther.handleCapabilities(Request{ID: "2", Method: "janus.capabilities"})
	toolsOther, ok := respOther.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	for _, tool := range toolsOther.EnabledTools {
		if tool == "janus.fs_read" {
			t.Fatal("did not expect fs_read to be enabled for other principal")
		}
	}
}

func TestValidateChangeSetBlocksForbiddenPaths(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-docs","action_type":"repo.apply_patch","resource":"file://workspace/docs/**","decision":"ALLOW","principals":["system"],"agents":["janus"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	params := `{"paths":["docs/readme.md","secrets.txt"]}`
	resp := server.handleValidateChangeSet(Request{ID: "1", Method: "repo.validate_change_set", Params: []byte(params)})
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map")
	}
	if result["allowed"].(bool) {
		t.Fatal("expected change set to be blocked")
	}
}
