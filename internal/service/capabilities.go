package service

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type CapabilityEnvelope struct {
	EnabledTools     []string `json:"enabled_tools"`
	SandboxModes     []string `json:"sandbox_modes"`
	NetworkMode      string   `json:"network_mode"`
	OutputMaxBytes   int      `json:"output_max_bytes"`
	OutputMaxLines   int      `json:"output_max_lines"`
	ApprovalsEnabled bool     `json:"approvals_enabled"`
}

func (s *Service) EnabledTools(id identity.VerifiedIdentity) []string {
	tools := []string{
		"nomos.fs_read",
		"nomos.fs_write",
		"nomos.apply_patch",
		"nomos.exec",
		"nomos.http_request",
		"repo.validate_change_set",
	}
	enabled := make([]string, 0)
	for _, tool := range tools {
		act, err := toolAction(tool, id)
		if err != nil {
			continue
		}
		normalized, err := normalize.Action(act)
		if err != nil {
			continue
		}
		decision := s.policy.Evaluate(normalized)
		if decision.Decision == policy.DecisionAllow {
			enabled = append(enabled, tool)
		}
	}
	sort.Strings(enabled)
	return enabled
}

func (s *Service) ValidateChangeSet(id identity.VerifiedIdentity, paths []string) (bool, []string, error) {
	blocked := make([]string, 0)
	for _, path := range paths {
		act := action.Action{
			SchemaVersion: "v1",
			ActionID:      "validate_change",
			ActionType:    "repo.apply_patch",
			Resource:      "file://workspace/" + path,
			Params:        []byte(`{}`),
			Principal:     id.Principal,
			Agent:         id.Agent,
			Environment:   id.Environment,
			Context:       action.Context{Extensions: map[string]json.RawMessage{}},
			TraceID:       "validate_change",
		}
		normalized, err := normalize.Action(act)
		if err != nil {
			blocked = append(blocked, path)
			continue
		}
		decision := s.policy.Evaluate(normalized)
		if decision.Decision != policy.DecisionAllow {
			blocked = append(blocked, path)
		}
	}
	return len(blocked) == 0, blocked, nil
}

func toolAction(tool string, id identity.VerifiedIdentity) (action.Action, error) {
	actionType := ""
	resource := ""
	switch tool {
	case "nomos.fs_read":
		actionType = "fs.read"
		resource = "file://workspace/README.md"
	case "nomos.fs_write":
		actionType = "fs.write"
		resource = "file://workspace/README.md"
	case "nomos.apply_patch":
		actionType = "repo.apply_patch"
		resource = "repo://local/workspace"
	case "nomos.exec":
		actionType = "process.exec"
		resource = "file://workspace/"
	case "nomos.http_request":
		actionType = "net.http_request"
		resource = "url://example.com/"
	case "repo.validate_change_set":
		actionType = "repo.validate_change_set"
		resource = "repo://local/workspace"
	default:
		return action.Action{}, errors.New("unknown tool")
	}
	return action.Action{
		SchemaVersion: "v1",
		ActionID:      "capability",
		ActionType:    actionType,
		Resource:      resource,
		Params:        []byte(`{}`),
		Principal:     id.Principal,
		Agent:         id.Agent,
		Environment:   id.Environment,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
		TraceID:       "capability",
	}, nil
}
