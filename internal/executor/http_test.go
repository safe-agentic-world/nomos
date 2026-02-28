package executor

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRunnerDeniesRedirectsByDefault(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewHTTPRunner(1024)
	_, err := runner.Do(redirect.URL, HTTPParams{Method: http.MethodGet})
	if !errors.Is(err, ErrRedirectDenied) {
		t.Fatalf("expected ErrRedirectDenied, got %v", err)
	}
}

func TestHTTPRunnerRedirectAllowlistAndFinalResource(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done?token=secret", http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewHTTPRunner(1024)
	result, err := runner.DoWithPolicy(redirect.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{
		Enabled:    true,
		HopLimit:   2,
		AllowHosts: []string{final.Listener.Addr().String()},
	})
	if err != nil {
		t.Fatalf("do with policy: %v", err)
	}
	if result.RedirectHops != 1 {
		t.Fatalf("expected 1 redirect hop, got %d", result.RedirectHops)
	}
	if result.FinalResource != "url://"+final.Listener.Addr().String()+"/done" {
		t.Fatalf("expected final resource, got %s", result.FinalResource)
	}
}

func TestHTTPRunnerRedirectHopLimit(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/step2", http.StatusFound)
	}))
	defer first.Close()

	runner := NewHTTPRunner(1024)
	_, err := runner.DoWithPolicy(first.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{
		Enabled:    true,
		HopLimit:   1,
		AllowHosts: []string{second.Listener.Addr().String(), final.Listener.Addr().String()},
	})
	if !errors.Is(err, ErrRedirectHopLimit) {
		t.Fatalf("expected ErrRedirectHopLimit, got %v", err)
	}
}
