package action

import (
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
)

func TestDecodeActionRequestRejectsUnknownFields(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}},"unknown":1}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestDecodeActionRequestAllowsContextExtensions(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{"foo":1,"bar":{"x":"y"}}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("expected extensions to be allowed, got %v", err)
	}
}

func TestDecodeActionRequestRejectsUnknownContextField(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"foo":"bar"}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected unknown context field error")
	}
}

func TestDecodeActionRequestRequiresSchemaVersion(t *testing.T) {
	payload := `{"action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected schema_version error")
	}
}

func TestDecodeActionRequestRequiresParamsAndContext(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","trace_id":"trace1"}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected params/context error")
	}
}

func TestDecodeActionRequestRejectsInvalidIDs(t *testing.T) {
	payload := `{"schema_version":"v1","action_id":"bad id","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected invalid action_id error")
	}
}

func TestDecodeActionRequestEnforcesParamsSize(t *testing.T) {
	large := strings.Repeat("x", MaxParamsBytes+1)
	payload := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{"data":"` + large + `"},"trace_id":"trace1","context":{"extensions":{}}}`
	_, err := DecodeActionRequest(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected params size error")
	}
}

func TestActionSchemaValidation(t *testing.T) {
	req := Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace1",
		Context:       Context{},
	}
	act, err := ToAction(req, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("expected schema validation to pass, got %v", err)
	}
	act.ActionType = ""
	if err := ValidateActionSchema(act); err == nil {
		t.Fatal("expected schema validation error for empty action_type")
	}
}
