package sandbox

import "testing"

func TestSelectProfile(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": "container",
	}
	_, err := SelectProfile(obligations, "local")
	if err == nil {
		t.Fatal("expected container requirement to fail with local profile")
	}
	profile, err := SelectProfile(obligations, "container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile != "container" {
		t.Fatalf("expected container, got %s", profile)
	}
}

func TestSelectProfileList(t *testing.T) {
	obligations := map[string]any{
		"sandbox_mode": []any{"local", "container"},
	}
	profile, err := SelectProfile(obligations, "container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile != "container" {
		t.Fatalf("expected container, got %s", profile)
	}
}
