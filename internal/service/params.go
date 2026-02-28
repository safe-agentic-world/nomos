package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/safe-agentic-world/janus/internal/executor"
)

type writeParams struct {
	Content string `json:"content"`
}

type patchParams struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type checkoutParams struct {
	SecretID string `json:"secret_id"`
}

func decodeWriteParams(raw []byte) (writeParams, error) {
	var params writeParams
	if err := decodeStrict(raw, &params); err != nil {
		return writeParams{}, err
	}
	if params.Content == "" {
		return writeParams{}, errors.New("content is required")
	}
	return params, nil
}

func decodePatchParams(raw []byte) (patchParams, error) {
	var params patchParams
	if err := decodeStrict(raw, &params); err != nil {
		return patchParams{}, err
	}
	if params.Path == "" || params.Content == "" {
		return patchParams{}, errors.New("path and content are required")
	}
	return params, nil
}

func decodeExecParams(raw []byte) (executor.ExecParams, error) {
	var params executor.ExecParams
	if err := decodeStrict(raw, &params); err != nil {
		return executor.ExecParams{}, err
	}
	if len(params.Argv) == 0 {
		return executor.ExecParams{}, errors.New("argv is required")
	}
	return params, nil
}

func decodeHTTPParams(raw []byte) (executor.HTTPParams, error) {
	var params executor.HTTPParams
	if err := decodeStrict(raw, &params); err != nil {
		return executor.HTTPParams{}, err
	}
	return params, nil
}

func decodeCheckoutParams(raw []byte) (checkoutParams, error) {
	var params checkoutParams
	if err := decodeStrict(raw, &params); err != nil {
		return checkoutParams{}, err
	}
	if strings.TrimSpace(params.SecretID) == "" {
		return checkoutParams{}, errors.New("secret_id is required")
	}
	return params, nil
}

func decodeStrict(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func parseURLFromResource(resource string) (string, string, error) {
	if !strings.HasPrefix(resource, "url://") {
		return "", "", errors.New("resource is not url")
	}
	raw := strings.TrimPrefix(resource, "url://")
	parsed, err := url.Parse("https://" + raw)
	if err != nil {
		return "", "", err
	}
	return parsed.Host, parsed.String(), nil
}

func execAllowed(obligations map[string]any, rawParams []byte) bool {
	allowlist, ok := obligations["exec_allowlist"]
	if !ok {
		return false
	}
	params, err := decodeExecParams(rawParams)
	if err != nil {
		return false
	}
	list, ok := allowlist.([]any)
	if !ok {
		return false
	}
	for _, entry := range list {
		prefix, ok := entry.([]any)
		if !ok {
			continue
		}
		if matchArgvPrefix(params.Argv, prefix) {
			return true
		}
	}
	return false
}

func matchArgvPrefix(argv []string, prefix []any) bool {
	if len(prefix) == 0 || len(argv) < len(prefix) {
		return false
	}
	for i, item := range prefix {
		value, ok := item.(string)
		if !ok || argv[i] != value {
			return false
		}
	}
	return true
}

func netAllowed(obligations map[string]any, host string) bool {
	list, ok := obligations["net_allowlist"]
	if !ok {
		return false
	}
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, entry := range items {
		if value, ok := entry.(string); ok && value == host {
			return true
		}
	}
	return false
}

func redactSecrets(text string, secrets []string) string {
	out := text
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = strings.ReplaceAll(out, s, "[REDACTED]")
	}
	return out
}
