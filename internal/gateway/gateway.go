package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/ai-developer-project/janus/internal/action"
	"github.com/ai-developer-project/janus/internal/audit"
	"github.com/ai-developer-project/janus/internal/executor"
	"github.com/ai-developer-project/janus/internal/identity"
	"github.com/ai-developer-project/janus/internal/policy"
	"github.com/ai-developer-project/janus/internal/redact"
	"github.com/ai-developer-project/janus/internal/service"
	"github.com/ai-developer-project/janus/internal/version"
)

type Gateway struct {
	cfg      Config
	server   *http.Server
	listener net.Listener
	writer   audit.Recorder
	policy   *policy.Engine
	service  *service.Service
	auth     *identity.Authenticator
	now      func() time.Time
}

func New(cfg Config) (*Gateway, error) {
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	writer, err := audit.NewWriter(cfg.Audit.Sink, redactor)
	if err != nil {
		return nil, err
	}
	bundle, err := policy.LoadBundle(cfg.Policy.BundlePath)
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(bundle)
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, writer, redactor, cfg.Executor.SandboxProfile, time.Now)
	authenticator := identity.NewAuthenticator(identity.AuthConfig{
		APIKeys:        cfg.Identity.APIKeys,
		ServiceSecrets: cfg.Identity.ServiceSecrets,
		AgentSecrets:   cfg.Identity.AgentSecrets,
		Environment:    cfg.Identity.Environment,
	})
	gw := &Gateway{
		cfg:     cfg,
		writer:  writer,
		policy:  engine,
		service: svc,
		auth:    authenticator,
		now:     time.Now,
	}
	return gw, nil
}

func NewWithRecorder(cfg Config, recorder audit.Recorder, now func() time.Time) (*Gateway, error) {
	if recorder == nil {
		return nil, errors.New("recorder is required")
	}
	if now == nil {
		now = time.Now
	}
	bundle, err := policy.LoadBundle(cfg.Policy.BundlePath)
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(bundle)
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, recorder, redactor, cfg.Executor.SandboxProfile, now)
	authenticator := identity.NewAuthenticator(identity.AuthConfig{
		APIKeys:        cfg.Identity.APIKeys,
		ServiceSecrets: cfg.Identity.ServiceSecrets,
		AgentSecrets:   cfg.Identity.AgentSecrets,
		Environment:    cfg.Identity.Environment,
	})
	gw := &Gateway{
		cfg:     cfg,
		writer:  recorder,
		policy:  engine,
		service: svc,
		auth:    authenticator,
		now:     now,
	}
	return gw, nil
}

func (g *Gateway) Start() error {
	if g.server != nil {
		return errors.New("gateway already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/version", g.handleVersion)
	mux.HandleFunc("/action", g.handleAction)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	g.server = server

	listener, err := net.Listen("tcp", g.cfg.Gateway.Listen)
	if err != nil {
		return err
	}
	g.listener = listener

	go func() {
		_ = server.Serve(listener)
	}()
	return nil
}

func (g *Gateway) Shutdown(ctx context.Context) error {
	if g.server == nil {
		return nil
	}
	return g.server.Shutdown(ctx)
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (g *Gateway) handleVersion(w http.ResponseWriter, _ *http.Request) {
	info := version.Current()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (g *Gateway) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	id, err := g.auth.Verify(r, body)
	if err != nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	req, err := action.DecodeActionRequestBytes(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	act, err := action.ToAction(req, id)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	resp, err := g.service.Process(act)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "execution_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) respondError(w http.ResponseWriter, status int, code string, message string) {
	resp := action.Response{
		Decision: policy.DecisionDeny,
		Reason:   code + ": " + message,
	}
	payload, _ := json.Marshal(resp)
	redacted := redact.DefaultRedactor().RedactBytes(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(redacted)
}

func (g *Gateway) emitTraceEvent(eventType, traceID, actionID string) {
	event := audit.Event{
		Timestamp: g.now().UTC(),
		EventType: eventType,
		TraceID:   traceID,
		ActionID:  actionID,
	}
	_ = g.writer.WriteEvent(event)
}
