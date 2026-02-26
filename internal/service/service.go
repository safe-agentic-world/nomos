package service

import (
	"errors"
	"time"

	"github.com/ai-developer-project/janus/internal/action"
	"github.com/ai-developer-project/janus/internal/audit"
	"github.com/ai-developer-project/janus/internal/executor"
	"github.com/ai-developer-project/janus/internal/normalize"
	"github.com/ai-developer-project/janus/internal/policy"
	"github.com/ai-developer-project/janus/internal/redact"
	"github.com/ai-developer-project/janus/internal/sandbox"
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
	sandboxProfile string
	now            func() time.Time
}

func New(policyEngine *policy.Engine, fsReader *executor.FSReader, fsWriter *executor.FSWriter, patcher *executor.PatchApplier, execRunner *executor.ExecRunner, httpRunner *executor.HTTPRunner, recorder audit.Recorder, redactor *redact.Redactor, sandboxProfile string, now func() time.Time) *Service {
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
		sandboxProfile: sandboxProfile,
		now:            now,
	}
}

func (s *Service) Process(actionInput action.Action) (action.Response, error) {
	if s.policy == nil || s.recorder == nil || s.redactor == nil {
		return action.Response{}, errors.New("service not initialized")
	}
	s.emitTraceEvent("trace.start", actionInput.TraceID, actionInput.ActionID)
	normalized, err := normalize.Action(actionInput)
	if err != nil {
		s.emitTraceEvent("trace.end", actionInput.TraceID, actionInput.ActionID)
		return action.Response{}, err
	}
	decision := s.policy.Evaluate(normalized)
	decisionEvent := audit.Event{
		Timestamp:   s.now().UTC(),
		EventType:   "action.decision",
		TraceID:     normalized.TraceID,
		ActionID:    normalized.ActionID,
		ActionType:  normalized.ActionType,
		Resource:    normalized.Resource,
		Principal:   normalized.Principal,
		Agent:       normalized.Agent,
		Environment: normalized.Environment,
		Decision:    decision.Decision,
		Reason:      decision.ReasonCode,
	}
	_ = s.recorder.WriteEvent(decisionEvent)
	response := action.Response{
		Decision: decision.Decision,
		Reason:   decision.ReasonCode,
		TraceID:  normalized.TraceID,
		ActionID: normalized.ActionID,
	}

	if decision.Decision != policy.DecisionAllow {
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	if normalized.ActionType == "fs.read" {
		readResult, err := s.fsReader.Read(normalized.Resource)
		if err != nil {
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return response, err
		}
		redacted := s.redactor.RedactText(readResult.Content)
		response.Output = redacted
		response.Truncated = readResult.Truncated
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	response.Obligations = decision.Obligations
	resp, err := s.handleAllowedAction(normalized, actionInput, decision.Obligations, response)
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
