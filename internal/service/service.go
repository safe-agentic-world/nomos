package service

import (
	"context"
	"errors"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
)

type Service struct {
	policy         *policy.Engine
	fsReader       *executor.FSReader
	fsWriter       *executor.FSWriter
	patcher        *executor.PatchApplier
	execRunner     *executor.ExecRunner
	httpRunner     *executor.HTTPRunner
	recorder       audit.Recorder
	redactor       *redact.Redactor
	approvals      ApprovalStore
	credentials    CredentialBroker
	sandboxProfile string
	now            func() time.Time
}

type ApprovalStore interface {
	CreateOrGetPending(ctx context.Context, req approval.PendingRequest) (approval.Record, error)
	CheckApproved(ctx context.Context, approvalID, fingerprint, classKey string) (bool, approval.Record, error)
}

type CredentialBroker interface {
	Checkout(secretID, principal, agent, environment, traceID string) (credentials.Lease, error)
	MaterializeEnv(leaseIDs []string, envAllowlist []string, principal, agent, environment, traceID string) (map[string]string, []string, error)
}

func New(policyEngine *policy.Engine, fsReader *executor.FSReader, fsWriter *executor.FSWriter, patcher *executor.PatchApplier, execRunner *executor.ExecRunner, httpRunner *executor.HTTPRunner, recorder audit.Recorder, redactor *redact.Redactor, approvals ApprovalStore, credentialBroker CredentialBroker, sandboxProfile string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{
		policy:         policyEngine,
		fsReader:       fsReader,
		fsWriter:       fsWriter,
		patcher:        patcher,
		execRunner:     execRunner,
		httpRunner:     httpRunner,
		recorder:       recorder,
		redactor:       redactor,
		approvals:      approvals,
		credentials:    credentialBroker,
		sandboxProfile: sandboxProfile,
		now:            now,
	}
}

func (s *Service) Process(actionInput action.Action) (action.Response, error) {
	if s.policy == nil || s.recorder == nil || s.redactor == nil {
		return action.Response{}, errors.New("service not initialized")
	}
	started := s.now().UTC()
	auditCtx := auditContext{
		resultClass:        resultInternalError,
		retryable:          true,
		riskLevel:          "low",
		riskFlags:          []string{},
		sandboxMode:        "none",
		networkMode:        "deny",
		credentialLeaseIDs: []string{},
		fallbackAction:     actionInput,
		fallbackTraceID:    actionInput.TraceID,
		fallbackActionID:   actionInput.ActionID,
		fallbackPrincipal:  actionInput.Principal,
		fallbackAgent:      actionInput.Agent,
		fallbackEnv:        actionInput.Environment,
		actionSummary:      actionSummary(actionInput.ActionType, actionInput.Resource),
		paramsSummary:      summarizeParams(s.redactor, actionInput.Params),
	}
	defer func() {
		s.emitCompletedAudit(auditCtx, started)
	}()

	s.emitTraceEvent("trace.start", actionInput.TraceID, actionInput.ActionID)
	normalized, err := normalize.Action(actionInput)
	if err != nil {
		auditCtx.resultClass = resultNormError
		auditCtx.retryable = false
		s.emitTraceEvent("trace.end", actionInput.TraceID, actionInput.ActionID)
		return action.Response{}, err
	}
	auditCtx.normalized = &normalized

	decision := s.policy.Evaluate(normalized)
	auditCtx.decision = decision
	auditCtx.riskLevel, auditCtx.riskFlags = riskVisibility(normalized)
	auditCtx.sandboxMode, auditCtx.networkMode = visibilityModes(decision.Obligations, s.sandboxProfile, normalized.ActionType)
	auditCtx.credentialLeaseIDs = credentialLeaseIDs(decision.Obligations)
	auditCtx.actionSummary = actionSummary(normalized.ActionType, normalized.Resource)
	fingerprint, err := actionFingerprint(normalized)
	if err != nil {
		auditCtx.resultClass = resultInternalError
		auditCtx.retryable = true
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return action.Response{}, err
	}
	decisionEvent := audit.Event{
		SchemaVersion:      "v1",
		Timestamp:          s.now().UTC(),
		EventType:          "action.decision",
		TraceID:            normalized.TraceID,
		ActionID:           normalized.ActionID,
		ActionType:         normalized.ActionType,
		Resource:           normalized.Resource,
		ResourceNormalized: normalized.Resource,
		ParamsHash:         normalized.ParamsHash,
		MatchedRuleIDs:     decision.MatchedRuleIDs,
		Obligations:        decision.Obligations,
		PolicyBundleHash:   decision.PolicyBundleHash,
		RiskLevel:          auditCtx.riskLevel,
		RiskFlags:          auditCtx.riskFlags,
		SandboxMode:        auditCtx.sandboxMode,
		NetworkMode:        auditCtx.networkMode,
		CredentialLeaseIDs: auditCtx.credentialLeaseIDs,
		ActionSummary:      auditCtx.actionSummary,
		Principal:          normalized.Principal,
		Agent:              normalized.Agent,
		Environment:        normalized.Environment,
		Decision:           decision.Decision,
		Reason:             decision.ReasonCode,
		Fingerprint:        fingerprint,
	}
	_ = s.recorder.WriteEvent(decisionEvent)
	response := action.Response{
		Decision:            decision.Decision,
		Reason:              decision.ReasonCode,
		TraceID:             normalized.TraceID,
		ActionID:            normalized.ActionID,
		ApprovalFingerprint: fingerprint,
	}
	response.Obligations = decision.Obligations

	if decision.Decision == policy.DecisionRequireApproval {
		classKey := approvalClassKey(decision.Obligations, normalized)
		approvalID, err := approvalIDFromExtensions(actionInput.Context)
		if err != nil {
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return action.Response{}, err
		}
		if approvalID != "" && s.approvals != nil {
			ok, rec, err := s.approvals.CheckApproved(context.Background(), approvalID, fingerprint, classKey)
			if err != nil {
				auditCtx.resultClass, auditCtx.retryable = classifyError(err)
				s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
				return action.Response{}, err
			}
			if ok {
				response.Decision = policy.DecisionAllow
				response.Reason = "allow_by_approval"
				response.ApprovalID = rec.ApprovalID
				_ = s.recorder.WriteEvent(audit.Event{
					Timestamp:   s.now().UTC(),
					EventType:   "approval.applied",
					TraceID:     normalized.TraceID,
					ActionID:    normalized.ActionID,
					ApprovalID:  rec.ApprovalID,
					Fingerprint: fingerprint,
					Principal:   normalized.Principal,
					Agent:       normalized.Agent,
					Environment: normalized.Environment,
				})
			}
		}
		if response.Decision != policy.DecisionAllow {
			if s.approvals != nil {
				scopeType := approval.ScopeFingerprint
				scopeKey := fingerprint
				if classKey != "" {
					scopeType = approval.ScopeClass
					scopeKey = classKey
				}
				pending, err := s.approvals.CreateOrGetPending(context.Background(), approval.PendingRequest{
					Fingerprint: fingerprint,
					ScopeType:   scopeType,
					ScopeKey:    scopeKey,
					TraceID:     normalized.TraceID,
					ActionID:    normalized.ActionID,
					ActionType:  normalized.ActionType,
					Resource:    normalized.Resource,
					ParamsHash:  normalized.ParamsHash,
					Principal:   normalized.Principal,
					Agent:       normalized.Agent,
					Environment: normalized.Environment,
				})
				if err != nil {
					auditCtx.resultClass, auditCtx.retryable = classifyError(err)
					s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
					return action.Response{}, err
				}
				response.ApprovalID = pending.ApprovalID
				response.ApprovalExpiresAt = pending.ExpiresAt.Format(time.RFC3339Nano)
				_ = s.recorder.WriteEvent(audit.Event{
					Timestamp:   s.now().UTC(),
					EventType:   "approval.requested",
					TraceID:     normalized.TraceID,
					ActionID:    normalized.ActionID,
					ApprovalID:  pending.ApprovalID,
					Fingerprint: fingerprint,
					ActionType:  normalized.ActionType,
					Resource:    normalized.Resource,
					Principal:   normalized.Principal,
					Agent:       normalized.Agent,
					Environment: normalized.Environment,
				})
			}
			auditCtx.resultSummary = summarizeResponse(s.redactor, response)
			auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return response, nil
		}
	}

	if response.Decision != policy.DecisionAllow {
		auditCtx.resultSummary = summarizeResponse(s.redactor, response)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	if normalized.ActionType == "fs.read" {
		readResult, err := s.fsReader.Read(normalized.Resource)
		if err != nil {
			auditCtx.resultClass, auditCtx.retryable = classifyError(err)
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return response, err
		}
		redacted := s.redactor.RedactText(readResult.Content)
		response.Output = redacted
		response.Truncated = readResult.Truncated
		auditCtx.executorMetadata = map[string]any{
			"bytes_read": readResult.BytesRead,
			"lines_read": readResult.LinesRead,
			"truncated":  readResult.Truncated,
		}
		auditCtx.resultSummary = summarizeResponse(s.redactor, response)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	resp, err := s.handleAllowedAction(normalized, actionInput, decision.Obligations, response)
	if err != nil {
		auditCtx.resultClass, auditCtx.retryable = classifyError(err)
	} else {
		auditCtx.resultSummary = summarizeResponse(s.redactor, resp)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, resp)
		switch normalized.ActionType {
		case "fs.write", "repo.apply_patch":
			auditCtx.executorMetadata = map[string]any{"bytes_written": resp.BytesWritten}
		case "process.exec":
			auditCtx.executorMetadata = map[string]any{"exit_code": resp.ExitCode, "truncated": resp.Truncated}
		case "net.http_request":
			auditCtx.executorMetadata = map[string]any{"status_code": resp.StatusCode, "truncated": resp.Truncated}
		}
	}
	s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
	return resp, err
}

func (s *Service) emitTraceEvent(eventType, traceID, actionID string) {
	event := audit.Event{
		Timestamp: s.now().UTC(),
		EventType: eventType,
		TraceID:   traceID,
		ActionID:  actionID,
	}
	_ = s.recorder.WriteEvent(event)
}

func (s *Service) ensureSandbox(obligations map[string]any) error {
	_, err := sandbox.SelectProfile(obligations, s.sandboxProfile)
	return err
}

func (s *Service) handleAllowedAction(normalized normalize.NormalizedAction, actionInput action.Action, obligations map[string]any, response action.Response) (action.Response, error) {
	switch normalized.ActionType {
	case "secrets.checkout":
		params, err := decodeCheckoutParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil
		}
		if s.credentials == nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "credentials_unavailable"
			return response, nil
		}
		lease, err := s.credentials.Checkout(params.SecretID, normalized.Principal, normalized.Agent, normalized.Environment, normalized.TraceID)
		if err != nil {
			return response, err
		}
		response.CredentialLeaseID = lease.ID
		return response, nil
	case "fs.write":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil
		}
		params, err := decodeWriteParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil
		}
		writeResult, err := s.fsWriter.Write(normalized.Resource, []byte(params.Content))
		if err != nil {
			return response, err
		}
		response.BytesWritten = writeResult.BytesWritten
		return response, nil
	case "repo.apply_patch":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil
		}
		params, err := decodePatchParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil
		}
		patchResult, err := s.patcher.Apply(params.Path, []byte(params.Content))
		if err != nil {
			return response, err
		}
		response.BytesWritten = patchResult.BytesWritten
		return response, nil
	case "process.exec":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil
		}
		if !execAllowed(obligations, actionInput.Params) {
			response.Decision = policy.DecisionDeny
			response.Reason = "exec_not_allowlisted"
			return response, nil
		}
		params, err := decodeExecParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil
		}
		if s.credentials != nil && len(params.CredentialLeaseIDs) > 0 {
			injected, secretValues, err := s.credentials.MaterializeEnv(params.CredentialLeaseIDs, params.EnvAllowlistKeys, normalized.Principal, normalized.Agent, normalized.Environment, normalized.TraceID)
			if err != nil {
				return response, err
			}
			params.InjectedEnv = injected
			response.CredentialLeaseIDs = append([]string{}, params.CredentialLeaseIDs...)
			result, err := s.execRunner.Run(params)
			if err != nil {
				return response, err
			}
			response.Stdout = redactSecrets(s.redactor.RedactText(result.Stdout), secretValues)
			response.Stderr = redactSecrets(s.redactor.RedactText(result.Stderr), secretValues)
			response.ExitCode = result.ExitCode
			response.Truncated = result.Truncated
			return response, nil
		}
		result, err := s.execRunner.Run(params)
		if err != nil {
			return response, err
		}
		response.Stdout = s.redactor.RedactText(result.Stdout)
		response.Stderr = s.redactor.RedactText(result.Stderr)
		response.ExitCode = result.ExitCode
		response.Truncated = result.Truncated
		return response, nil
	case "net.http_request":
		host, urlString, err := parseURLFromResource(normalized.Resource)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_resource"
			return response, nil
		}
		if !netAllowed(obligations, host) {
			response.Decision = policy.DecisionDeny
			response.Reason = "net_not_allowlisted"
			return response, nil
		}
		params, err := decodeHTTPParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil
		}
		result, err := s.httpRunner.Do(urlString, params)
		if err != nil {
			return response, err
		}
		response.StatusCode = result.StatusCode
		response.Output = s.redactor.RedactText(result.Body)
		response.Truncated = result.Truncated
		return response, nil
	default:
		response.Decision = policy.DecisionDeny
		response.Reason = "unsupported_action"
		return response, nil
	}
}
