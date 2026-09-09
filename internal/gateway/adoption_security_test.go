package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
)

func TestReviewerEndpointsRequireExplicitAuthority(t *testing.T) {
	for _, endpoint := range []string{"regular", "ui"} {
		for _, tc := range []struct {
			name       string
			token      string
			principals []string
			status     int
		}{
			{"unauthenticated", "", []string{"system"}, http.StatusUnauthorized},
			{"invalid token", "wrong", []string{"system"}, http.StatusUnauthorized},
			{"not a reviewer", "ui-key", []string{"reviewer"}, http.StatusForbidden},
			{"empty allowlist", "ui-key", nil, http.StatusForbidden},
			{"authorized reviewer", "ui-key", []string{"system"}, http.StatusOK},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				gw := newUITestGateway(t)
				gw.cfg.Approvals.ApproverPrincipals = tc.principals
				record, err := gw.approvals.CreateOrGetPending(context.Background(), approval.PendingRequest{
					Fingerprint: "fp", ScopeType: approval.ScopeFingerprint, ScopeKey: "fp",
					TraceID: "trace", ActionID: "action", ActionType: "email.send",
					Resource: "inbox://local/messages/1", ParamsHash: "params",
					Principal: "system", Agent: "nomos", Environment: "dev",
				})
				if err != nil {
					t.Fatal(err)
				}
				id := record.ApprovalID
				req := httptest.NewRequest(http.MethodPost, "/approvals/decide", strings.NewReader(`{"approval_id":"`+id+`","decision":"APPROVE"}`))
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				w := httptest.NewRecorder()
				if endpoint == "ui" {
					gw.handleUIApprovalDecision(w, req)
				} else {
					gw.handleApprovalDecision(w, req)
				}
				if w.Code != tc.status {
					t.Fatalf("got %d, want %d: %s", w.Code, tc.status, w.Body.String())
				}
				if tc.status != http.StatusOK {
					after, err := gw.approvals.Lookup(context.Background(), id)
					if err != nil || after.Status != approval.StatusPending {
						t.Fatalf("unauthorized decision changed approval: %+v %v", after, err)
					}
				}
			})
		}
	}
}

func TestUnconfiguredApprovalWebhooksAreDisabled(t *testing.T) {
	gw := newUITestGateway(t)
	for name, handler := range map[string]http.HandlerFunc{
		"generic": gw.handleApprovalDecisionWebhook,
		"slack":   gw.handleSlackApprovalWebhook,
		"teams":   gw.handleTeamsApprovalWebhook,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(http.MethodPost, "/webhooks/approvals", strings.NewReader(`{}`)))
			if w.Code != http.StatusNotFound {
				t.Fatalf("expected disabled route, got %d", w.Code)
			}
		})
	}
}

type unavailableAudit struct{}

func (unavailableAudit) WriteEvent(audit.Event) error { return errors.New("sensitive storage detail") }

func TestExternalReportDoesNotClaimSuccessWhenAuditFails(t *testing.T) {
	gw := newUITestGateway(t)
	originalWriter := gw.writer
	defer func() { gw.writer = originalWriter }()
	gw.writer = unavailableAudit{}
	body := `{"schema_version":"v1","action_id":"report-failure","trace_id":"report-failure","action_type":"email.send","resource":"inbox://local/messages/1","outcome":"SUCCEEDED"}`
	req := httptest.NewRequest(http.MethodPost, "/actions/report", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ui-key")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleExternalReport(w, req)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"recorded":true`) || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatalf("unexpected report failure: %d %s", w.Code, w.Body.String())
	}
}
