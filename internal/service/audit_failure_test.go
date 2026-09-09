package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type failedDecisionRecorder struct{}

func (failedDecisionRecorder) WriteEvent(event audit.Event) error {
	if event.EventType == "action.decision" {
		return errors.New("sensitive storage detail")
	}
	return nil
}

func TestAuditFailureCannotReturnExternalAuthorization(t *testing.T) {
	svc, _ := newCustomActionService(t, policy.Bundle{
		Version: "v1", Hash: "audit-failure",
		Rules: []policy.Rule{{ID: "allow-send", ActionType: "email.send", Resource: "inbox://local/messages/*", Decision: policy.DecisionAllow}},
	}, nil)
	svc.recorder = failedDecisionRecorder{}
	response, err := svc.Process(mustCustomAction(t, "audit-failure", "audit-failure", "email.send", "inbox://local/messages/1", `{}`, ""))
	if err == nil || response.ExecutionMode != "" {
		t.Fatalf("unexpected authorization on audit failure: %+v %v", response, err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("audit implementation detail leaked")
	}
}
