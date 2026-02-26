package executor

import (
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPParams struct {
	Method string            `json:"method"`
	Body   string            `json:"body"`
	Header map[string]string `json:"headers"`
}

type HTTPResult struct {
	StatusCode int
	Body       string
	Truncated  bool
}

type HTTPRunner struct {
	client   *http.Client
	maxBytes int
}

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
	resp, err := r.client.Do(req)
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
	return HTTPResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Truncated:  truncated,
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
