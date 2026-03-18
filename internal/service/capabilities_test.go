package service

import (
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestToolCapabilitiesClassifyAllowRequireApprovalMixedAndUnavailable(t *testing.T) {
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-read",
				ActionType:   "fs.read",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "approve-http",
				ActionType:   "net.http_request",
				Resource:     "url://shop.example.com/checkout/**",
				Decision:     policy.DecisionRequireApproval,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "approve-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionRequireApproval,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "allow-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
		},
	})
	svc := &Service{policy: engine}
	id := identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}

	capabilities := svc.ToolCapabilities(id)
	if got := capabilities["nomos.fs_read"].State; got != ToolStateAllow {
		t.Fatalf("expected fs_read allow, got %q", got)
	}
	if got := capabilities["nomos.http_request"].State; got != ToolStateRequireApproval {
		t.Fatalf("expected http_request require_approval, got %q", got)
	}
	if got := capabilities["nomos.exec"].State; got != ToolStateMixed {
		t.Fatalf("expected exec mixed, got %q", got)
	}
	if got := capabilities["nomos.fs_write"].State; got != ToolStateUnavailable {
		t.Fatalf("expected fs_write unavailable, got %q", got)
	}
	if got := capabilities["repo.validate_change_set"].State; got != ToolStateUnavailable {
		t.Fatalf("expected validate_change_set unavailable without repo.apply_patch support, got %q", got)
	}
}

func TestCapabilityEnvelopeFromToolStatesPreservesLegacyEnabledToolsAndNewBuckets(t *testing.T) {
	envelope := CapabilityEnvelopeFromToolStates(map[string]ToolCapability{
		"nomos.fs_read": {
			Name:                "nomos.fs_read",
			ActionType:          "fs.read",
			State:               ToolStateAllow,
			ImmediatelyCallable: true,
			Advertised:          true,
		},
		"nomos.http_request": {
			Name:             "nomos.http_request",
			ActionType:       "net.http_request",
			State:            ToolStateRequireApproval,
			ApprovalRequired: true,
			Advertised:       true,
		},
		"nomos.exec": {
			Name:                "nomos.exec",
			ActionType:          "process.exec",
			State:               ToolStateMixed,
			ImmediatelyCallable: true,
			ApprovalRequired:    true,
			Advertised:          true,
		},
		"nomos.fs_write": {
			Name:       "nomos.fs_write",
			ActionType: "fs.write",
			State:      ToolStateUnavailable,
			Advertised: true,
		},
	})

	if envelope.ToolAdvertisementMode != "mcp_tools_list_static" {
		t.Fatalf("expected static tool advertisement mode, got %q", envelope.ToolAdvertisementMode)
	}
	if len(envelope.EnabledTools) != 3 {
		t.Fatalf("expected 3 enabled tools, got %+v", envelope.EnabledTools)
	}
	if len(envelope.ImmediateTools) != 1 || envelope.ImmediateTools[0] != "nomos.fs_read" {
		t.Fatalf("unexpected immediate tools: %+v", envelope.ImmediateTools)
	}
	if len(envelope.ApprovalGatedTools) != 1 || envelope.ApprovalGatedTools[0] != "nomos.http_request" {
		t.Fatalf("unexpected approval-gated tools: %+v", envelope.ApprovalGatedTools)
	}
	if len(envelope.MixedTools) != 1 || envelope.MixedTools[0] != "nomos.exec" {
		t.Fatalf("unexpected mixed tools: %+v", envelope.MixedTools)
	}
	if len(envelope.UnavailableTools) != 1 || envelope.UnavailableTools[0] != "nomos.fs_write" {
		t.Fatalf("unexpected unavailable tools: %+v", envelope.UnavailableTools)
	}
}
