package executor

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type HTTPParams struct {
	Method string            `json:"method"`
	Body   string            `json:"body"`
	Header map[string]string `json:"headers"`
}

type HTTPResult struct {
	StatusCode    int
	Body          string
	Truncated     bool
	FinalResource string
	RedirectHops  int
}

type RedirectPolicy struct {
	Enabled    bool
	HopLimit   int
	AllowHosts []string
}

type HTTPRunner struct {
	client   *http.Client
	maxBytes int
}

var (
	ErrRedirectDenied         = errors.New("http redirects are not allowed")
	ErrRedirectHopLimit       = errors.New("http redirect hop limit exceeded")
	ErrRedirectDisallowedHost = errors.New("http redirect destination is not allowlisted")
	ErrRedirectInvalidTarget  = errors.New("http redirect target is invalid")
)

func NewHTTPRunner(maxBytes int) *HTTPRunner {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return &HTTPRunner{
		client:   &http.Client{Timeout: 5 * time.Second},
		maxBytes: maxBytes,
	}
}

func (r *HTTPRunner) Do(url string, params HTTPParams) (HTTPResult, error) {
	return r.DoWithPolicy(url, params, RedirectPolicy{})
}

func (r *HTTPRunner) DoWithPolicy(url string, params HTTPParams, policy RedirectPolicy) (HTTPResult, error) {
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	reader := strings.NewReader(params.Body)
	req, err := http.NewRequest(params.Method, url, reader)
	if err != nil {
		return HTTPResult{}, err
	}
	for key, value := range params.Header {
		req.Header.Set(key, value)
	}
	client := *r.client
	redirectHops := 0
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		redirectHops = len(via)
		if !policy.Enabled {
			return ErrRedirectDenied
		}
		limit := policy.HopLimit
		if limit <= 0 {
			limit = 3
		}
		if len(via) > limit {
			return ErrRedirectHopLimit
		}
		normalized, err := normalize.NormalizeRedirectURL(next.URL.String())
		if err != nil {
			return ErrRedirectInvalidTarget
		}
		if !hostAllowlisted(policy.AllowHosts, hostFromNormalizedURL(normalized)) {
			return ErrRedirectDisallowedHost
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{}, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, int64(r.maxBytes+1))
	body, err := io.ReadAll(limited)
	if err != nil {
		return HTTPResult{}, err
	}
	truncated := len(body) > r.maxBytes
	if truncated {
		body = body[:r.maxBytes]
	}
	finalURL := req.URL.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	finalResource, err := normalize.NormalizeRedirectURL(finalURL)
	if err != nil {
		return HTTPResult{}, ErrRedirectInvalidTarget
	}
	return HTTPResult{
		StatusCode:    resp.StatusCode,
		Body:          string(body),
		Truncated:     truncated,
		FinalResource: finalResource,
		RedirectHops:  redirectHops,
	}, nil
}

func (r *HTTPRunner) Client() *http.Client {
	return r.client
}

func (r *HTTPRunner) SetClient(client *http.Client) {
	if client != nil {
		r.client = client
	}
}

func hostAllowlisted(allowHosts []string, host string) bool {
	for _, allowed := range allowHosts {
		if strings.TrimSpace(allowed) == host {
			return true
		}
	}
	return false
}

func hostFromNormalizedURL(resource string) string {
	trimmed := strings.TrimPrefix(resource, "url://")
	idx := strings.Index(trimmed, "/")
	if idx == -1 {
		return trimmed
	}
	return trimmed[:idx]
}
