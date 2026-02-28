package service

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

const helperCredentialEchoArg = "nomos-helper-credential-echo"

func TestCredentialBrokerLeaseAndExecInjectionNoLeak(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os executable: %v", err)
	}
	helperArgv := []string{exe, "-test.run=^TestHelperProcessCredentialEcho$", "--", helperCredentialEchoArg}
	helperAllowlist := make([]any, len(helperArgv))
	for i, arg := range helperArgv {
		helperAllowlist[i] = arg
	}
	broker, err := credentials.NewBroker([]credentials.Secret{{ID: "gh_token", EnvKey: "API_TOKEN", Value: "super-secret-token", TTLSeconds: 60}}, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	bundle := policy.Bundle{Version: "v1", Hash: "h", Rules: []policy.Rule{
		{ID: "allow-checkout", ActionType: "secrets.checkout", Resource: "secret://vault/github", Decision: policy.DecisionAllow},
		{ID: "allow-exec", ActionType: "process.exec", Resource: "file://workspace/**", Decision: policy.DecisionAllow, Obligations: map[string]any{"sandbox_mode": "local", "exec_allowlist": []any{helperAllowlist}}},
	}}
	svc := New(policy.NewEngine(bundle), executor.NewFSReader(dir, 64*1024, 200), executor.NewFSWriter(dir, 64*1024), executor.NewPatchApplier(dir, 64*1024), executor.NewExecRunner(dir, 64*1024), executor.NewHTTPRunner(64*1024), &recordSink{}, redact.DefaultRedactor(), nil, broker, "local", func() time.Time { return time.Unix(0, 0) })

	checkoutAct, err := action.ToAction(action.Request{SchemaVersion: "v1", ActionID: "a1", ActionType: "secrets.checkout", Resource: "secret://vault/github", Params: []byte(`{"secret_id":"gh_token"}`), TraceID: "t1", Context: action.Context{Extensions: map[string]json.RawMessage{}}}, identity.VerifiedIdentity{Principal: "p", Agent: "a", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action checkout: %v", err)
	}
	checkoutResp, err := svc.Process(checkoutAct)
	if err != nil {
		t.Fatalf("process checkout: %v", err)
	}
	if checkoutResp.CredentialLeaseID == "" {
		t.Fatal("expected lease id")
	}
	if strings.Contains(checkoutResp.Output, "super-secret-token") {
		t.Fatal("secret should never be returned")
	}

	execParams, err := json.Marshal(map[string]any{
		"argv":                 helperArgv,
		"cwd":                  "",
		"env_allowlist_keys":   []string{"API_TOKEN"},
		"credential_lease_ids": []string{checkoutResp.CredentialLeaseID},
	})
	if err != nil {
		t.Fatalf("marshal exec params: %v", err)
	}
	execAct, err := action.ToAction(action.Request{SchemaVersion: "v1", ActionID: "a2", ActionType: "process.exec", Resource: "file://workspace/", Params: execParams, TraceID: "t1", Context: action.Context{Extensions: map[string]json.RawMessage{}}}, identity.VerifiedIdentity{Principal: "p", Agent: "a", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action exec: %v", err)
	}
	execResp, err := svc.Process(execAct)
	if err != nil {
		t.Fatalf("process exec: %v", err)
	}
	if execResp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", execResp.Decision)
	}
	if strings.Contains(execResp.Stdout, "super-secret-token") {
		t.Fatalf("secret leaked in stdout: %s", execResp.Stdout)
	}
	if !strings.Contains(execResp.Stdout, "[REDACTED]") {
		t.Fatalf("expected redacted secret in stdout, got %s", execResp.Stdout)
	}
}

func TestHelperProcessCredentialEcho(t *testing.T) {
	if !containsArg(os.Args, helperCredentialEchoArg) {
		return
	}
	_, _ = os.Stdout.WriteString(os.Getenv("API_TOKEN"))
	os.Exit(0)
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
