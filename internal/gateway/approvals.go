package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type approvalDecisionRequest struct {
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"`
}

type slackApprovalDecisionRequest struct {
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"`
	UserID     string `json:"user_id"`
	ChannelID  string `json:"channel_id"`
	Comment    string `json:"comment,omitempty"`
}

type teamsApprovalDecisionRequest struct {
	ApprovalID     string `json:"approval_id"`
	Decision       string `json:"decision"`
	UserAADID      string `json:"user_aad_id"`
	ConversationID string `json:"conversation_id"`
	Comment        string `json:"comment,omitempty"`
}

func (g *Gateway) handleApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !g.cfg.Approvals.Enabled || g.approvals == nil {
		g.respondError(w, http.StatusNotFound, "not_enabled", "approvals are not enabled")
		return
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	req, err := decodeApprovalDecisionRequest(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	g.applyApprovalDecision(w, r, req, "approval.decided")
}

func (g *Gateway) handleApprovalDecisionWebhook(w http.ResponseWriter, r *http.Request) {
	if g.cfg.Approvals.WebhookToken != "" {
		token := strings.TrimSpace(r.Header.Get("X-Nomos-Webhook-Token"))
		if token == "" || token != g.cfg.Approvals.WebhookToken {
			g.respondError(w, http.StatusUnauthorized, "auth_error", "invalid webhook token")
			return
		}
	}
	g.handleApprovalDecision(w, r)
}

func (g *Gateway) handleSlackApprovalWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !g.cfg.Approvals.Enabled || g.approvals == nil {
		g.respondError(w, http.StatusNotFound, "not_enabled", "approvals are not enabled")
		return
	}
	if g.cfg.Approvals.SlackToken != "" {
		token := strings.TrimSpace(r.Header.Get("X-Nomos-Slack-Token"))
		if token == "" || token != g.cfg.Approvals.SlackToken {
			g.respondError(w, http.StatusUnauthorized, "auth_error", "invalid slack token")
			return
		}
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	req, err := decodeSlackApprovalDecisionRequest(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	g.applyApprovalDecision(w, r, approvalDecisionRequest{ApprovalID: req.ApprovalID, Decision: req.Decision}, "approval.decided.slack")
}

func (g *Gateway) handleTeamsApprovalWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !g.cfg.Approvals.Enabled || g.approvals == nil {
		g.respondError(w, http.StatusNotFound, "not_enabled", "approvals are not enabled")
		return
	}
	if g.cfg.Approvals.TeamsToken != "" {
		token := strings.TrimSpace(r.Header.Get("X-Nomos-Teams-Token"))
		if token == "" || token != g.cfg.Approvals.TeamsToken {
			g.respondError(w, http.StatusUnauthorized, "auth_error", "invalid teams token")
			return
		}
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	req, err := decodeTeamsApprovalDecisionRequest(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	g.applyApprovalDecision(w, r, approvalDecisionRequest{ApprovalID: req.ApprovalID, Decision: req.Decision}, "approval.decided.teams")
}

func (g *Gateway) applyApprovalDecision(w http.ResponseWriter, r *http.Request, req approvalDecisionRequest, eventType string) {
	rec, err := g.approvals.Decide(r.Context(), req.ApprovalID, req.Decision)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, approval.ErrNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, approval.ErrAlreadyFinalized) {
			status = http.StatusConflict
		}
		g.respondError(w, status, "approval_error", err.Error())
		return
	}
	_ = g.writer.WriteEvent(audit.Event{
		Timestamp:   g.now().UTC(),
		EventType:   eventType,
		TraceID:     rec.TraceID,
		ActionID:    rec.ActionID,
		ApprovalID:  rec.ApprovalID,
		Fingerprint: rec.Fingerprint,
		ActionType:  rec.ActionType,
		Resource:    rec.Resource,
		Principal:   rec.Principal,
		Agent:       rec.Agent,
		Environment: rec.Environment,
		Decision:    rec.Status,
	})
	resp := action.Response{
		Decision:            policy.DecisionAllow,
		Reason:              "approval_recorded",
		ApprovalID:          rec.ApprovalID,
		ApprovalFingerprint: rec.Fingerprint,
		ApprovalExpiresAt:   rec.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func decodeApprovalDecisionRequest(data []byte) (approvalDecisionRequest, error) {
	var req approvalDecisionRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return approvalDecisionRequest{}, err
	}
	req.ApprovalID = strings.TrimSpace(req.ApprovalID)
	req.Decision = strings.TrimSpace(req.Decision)
	if req.ApprovalID == "" || req.Decision == "" {
		return approvalDecisionRequest{}, errors.New("approval_id and decision are required")
	}
	return req, nil
}

func decodeSlackApprovalDecisionRequest(data []byte) (slackApprovalDecisionRequest, error) {
	var req slackApprovalDecisionRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return slackApprovalDecisionRequest{}, err
	}
	req.ApprovalID = strings.TrimSpace(req.ApprovalID)
	req.Decision = strings.TrimSpace(req.Decision)
	req.UserID = strings.TrimSpace(req.UserID)
	req.ChannelID = strings.TrimSpace(req.ChannelID)
	if req.ApprovalID == "" || req.Decision == "" || req.UserID == "" || req.ChannelID == "" {
		return slackApprovalDecisionRequest{}, errors.New("approval_id, decision, user_id, and channel_id are required")
	}
	return req, nil
}

func decodeTeamsApprovalDecisionRequest(data []byte) (teamsApprovalDecisionRequest, error) {
	var req teamsApprovalDecisionRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return teamsApprovalDecisionRequest{}, err
	}
	req.ApprovalID = strings.TrimSpace(req.ApprovalID)
	req.Decision = strings.TrimSpace(req.Decision)
	req.UserAADID = strings.TrimSpace(req.UserAADID)
	req.ConversationID = strings.TrimSpace(req.ConversationID)
	if req.ApprovalID == "" || req.Decision == "" || req.UserAADID == "" || req.ConversationID == "" {
		return teamsApprovalDecisionRequest{}, errors.New("approval_id, decision, user_aad_id, and conversation_id are required")
	}
	return req, nil
}

func decodeStrictJSON(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data")
	}
	return nil
}
