package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalGuardRejectsBuiltInsAndMissingExternalMode(t *testing.T) {
	for _, tc := range []struct {
		actionType, mode string
		requests         int
	}{
		{"net.http_request", "external_authorized", 0},
		{"process.exec", "external_authorized", 0},
		{"email.send", "", 1},
		{"email.send", "nomos_executed", 1},
	} {
		t.Run(tc.actionType+"/"+tc.mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW", ExecutionMode: tc.mode})
			}))
			defer server.Close()
			executed := false
			guard, err := NewGuardedFunction(mustTestClient(t, server.URL),
				func(string) (ActionRequest, error) {
					return NewActionRequest(tc.actionType, "inbox://local/messages/1", map[string]any{}), nil
				},
				func(context.Context, string) (string, error) { executed = true; return "bad", nil })
			if err != nil {
				t.Fatal(err)
			}
			result, err := guard.Invoke(context.Background(), "ignored")
			if err == nil || result.Executed || executed || calls != tc.requests {
				t.Fatalf("guard failed closed incorrectly: %+v %v calls=%d", result, err, calls)
			}
		})
	}
}
