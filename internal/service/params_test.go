package service

import "testing"

func TestExecAllowlist(t *testing.T) {
	obligations := map[string]any{
		"exec_allowlist": []any{
			[]any{"git"},
			[]any{"go", "test"},
		},
	}
	ok := execAllowed(obligations, []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`))
	if !ok {
		t.Fatal("expected exec allowlist to allow git")
	}
	ok = execAllowed(obligations, []byte(`{"argv":["bash","-c","ls"],"cwd":"","env_allowlist_keys":[]}`))
	if ok {
		t.Fatal("expected exec allowlist to block bash")
	}
}

func TestNetAllowlist(t *testing.T) {
	obligations := map[string]any{
		"net_allowlist": []any{"example.com"},
	}
	if !netAllowed(obligations, "example.com") {
		t.Fatal("expected host allowed")
	}
	if netAllowed(obligations, "evil.com") {
		t.Fatal("expected host blocked")
	}
}
