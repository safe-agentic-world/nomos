package service

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/janus/internal/action"
	"github.com/safe-agentic-world/janus/internal/audit"
	"github.com/safe-agentic-world/janus/internal/executor"
	"github.com/safe-agentic-world/janus/internal/identity"
	"github.com/safe-agentic-world/janus/internal/policy"
	"github.com/safe-agentic-world/janus/internal/redact"
)

type recordSink struct {
	events []audit.Event
}

func (r *recordSink) WriteEvent(event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func TestServiceAllowsReadAndRedacts(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	content := "Authorization: secret\n" + strings.Repeat("x", 100) + "\n"
	if err := os.WriteFile(readmePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	recorder := &recordSink{}
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("ok"))
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", resp.Decision)
	}
	if resp.Output == "" {
		t.Fatal("expected output")
	}
	if strings.Contains(resp.Output, "Authorization: secret") {
		t.Fatal("expected redaction")
	}
	if !resp.Truncated {
		t.Fatal("expected truncated output")
	}
	if len(resp.Output) > 32 {
		t.Fatalf("expected output <= 32 bytes, got %d", len(resp.Output))
	}
	if len(recorder.events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(recorder.events))
	}
	decisionEvent := recorder.events[1]
	if decisionEvent.Principal != "system" || decisionEvent.Agent != "janus" || decisionEvent.Environment != "dev" {
		t.Fatalf("expected identity in audit event, got principal=%s agent=%s env=%s", decisionEvent.Principal, decisionEvent.Agent, decisionEvent.Environment)
	}
}

func TestServiceDeniesRead(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	recorder := &recordSink{}
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("ok"))
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act2",
		ActionType:    "fs.read",
		Resource:      "file://workspace/other.md",
		Params:        []byte(`{}`),
		TraceID:       "trace2",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Output != "" {
		t.Fatal("expected no output on deny")
	}
	if len(recorder.events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(recorder.events))
	}
}

func TestServiceHTTPAllowlist(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-http",
				ActionType:   "net.http_request",
				Resource:     "url://example.com/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"janus"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"net_allowlist": []any{"example.com"},
				},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("hello"))
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act3",
		ActionType:    "net.http_request",
		Resource:      "url://example.com/path",
		Params:        []byte(`{"method":"GET"}`),
		TraceID:       "trace3",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", resp.Decision)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Output == "" {
		t.Fatal("expected body output")
	}
}

func TestServiceExecRequiresAllowlist(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"janus"},
				Environments: []string{"dev"},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act4",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        []byte(`{"argv":["cmd","/c","echo","hi"],"cwd":"","env_allowlist_keys":[]}`),
		TraceID:       "trace4",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Reason != "exec_not_allowlisted" {
		t.Fatalf("expected exec_not_allowlisted, got %s", resp.Reason)
	}
}

func TestServiceSandboxRequired(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-write",
				ActionType:   "fs.write",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"janus"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"sandbox_mode": "container",
				},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act5",
		ActionType:    "fs.write",
		Resource:      "file://workspace/output.txt",
		Params:        []byte(`{"content":"data"}`),
		TraceID:       "trace5",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "janus",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Reason != "sandbox_required" {
		t.Fatalf("expected sandbox_required, got %s", resp.Reason)
	}
}

func newTestHTTPClient(body string) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
