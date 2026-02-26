package normalize

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/ai-developer-project/janus/internal/action"
	"github.com/ai-developer-project/janus/internal/canonicaljson"
)

type NormalizedAction struct {
	SchemaVersion    string
	ActionID         string
	ActionType       string
	Resource         string
	Params           []byte
	ParamsHash       string
	Principal        string
	Agent            string
	Environment      string
	Context          action.Context
	TraceID          string
	TraceActionCount int
}

func Action(input action.Action) (NormalizedAction, error) {
	if strings.TrimSpace(input.ActionType) == "" {
		return NormalizedAction{}, errors.New("action_type is required")
	}
	if strings.TrimSpace(input.Resource) == "" {
		return NormalizedAction{}, errors.New("resource is required")
	}
	normalizedResource, err := normalizeResource(strings.TrimSpace(input.Resource))
	if err != nil {
		return NormalizedAction{}, err
	}
	canonicalParams, err := canonicaljson.Canonicalize(input.Params)
	if err != nil {
		return NormalizedAction{}, fmt.Errorf("params canonicalization failed: %w", err)
	}
	paramsHash := canonicaljson.HashSHA256(canonicalParams)
	return NormalizedAction{
		SchemaVersion: input.SchemaVersion,
		ActionID:      input.ActionID,
		ActionType:    strings.TrimSpace(input.ActionType),
		Resource:      normalizedResource,
		Params:        canonicalParams,
		ParamsHash:    paramsHash,
		Principal:     input.Principal,
		Agent:         input.Agent,
		Environment:   input.Environment,
		Context:       input.Context,
		TraceID:       input.TraceID,
	}, nil
}

func normalizeResource(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid resource uri: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "file":
		return normalizeFileResource(parsed)
	case "repo":
		return normalizeRepoResource(parsed)
	case "url":
		return normalizeURLResource(parsed)
	default:
		return "", fmt.Errorf("unsupported resource scheme %q", parsed.Scheme)
	}
}

func normalizeFileResource(parsed *url.URL) (string, error) {
	host := strings.ToLower(parsed.Host)
	if host == "" {
		host = "workspace"
	}
	if host != "workspace" {
		return "", fmt.Errorf("unsupported file host %q", parsed.Host)
	}
	if hasTraversalSegments(parsed.Path) {
		return "", errors.New("file path traversal detected")
	}
	cleaned := cleanPath(parsed.Path)
	if cleaned == "" {
		return "", errors.New("file path is required")
	}
	return "file://" + host + cleaned, nil
}

func normalizeRepoResource(parsed *url.URL) (string, error) {
	if parsed.Host == "" {
		return "", errors.New("repo host is required")
	}
	org := strings.ToLower(parsed.Host)
	repo := strings.ToLower(strings.TrimPrefix(parsed.Path, "/"))
	if repo == "" || strings.Contains(repo, "/") {
		return "", errors.New("repo path must be single segment")
	}
	return "repo://" + org + "/" + repo, nil
}

func normalizeURLResource(parsed *url.URL) (string, error) {
	host := strings.ToLower(parsed.Host)
	if host == "" {
		return "", errors.New("url host is required")
	}
	hostName, port, err := net.SplitHostPort(host)
	if err == nil {
		if port == "80" || port == "443" {
			host = hostName
		}
	} else {
		if strings.Contains(host, ":") && !strings.Contains(host, "]") {
			return "", errors.New("invalid url host")
		}
	}
	if hasTraversalSegments(parsed.Path) {
		return "", errors.New("url path traversal detected")
	}
	cleaned := cleanPath(parsed.Path)
	return "url://" + host + cleaned, nil
}

func cleanPath(raw string) string {
	if raw == "" {
		return ""
	}
	cleaned := path.Clean("/" + strings.ReplaceAll(raw, "\\", "/"))
	if cleaned == "/" {
		return "/"
	}
	return cleaned
}

func hasTraversalSegments(raw string) bool {
	if raw == "" {
		return false
	}
	segments := strings.Split(strings.ReplaceAll(raw, "\\", "/"), "/")
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func MatchPattern(pattern, value string) (bool, error) {
	if strings.Contains(pattern, "\\") || strings.Contains(value, "\\") {
		return false, errors.New("backslash is not allowed")
	}
	patternSegments := strings.Split(pattern, "/")
	valueSegments := strings.Split(value, "/")
	return matchSegments(patternSegments, valueSegments), nil
}

func matchSegments(pattern, value []string) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(value); i++ {
			if matchSegments(pattern[1:], value[i:]) {
				return true
			}
		}
		return false
	}
	if len(value) == 0 {
		return false
	}
	if !matchSegment(pattern[0], value[0]) {
		return false
	}
	return matchSegments(pattern[1:], value[1:])
}

func matchSegment(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return matchWildcard(pattern, value)
}

func matchWildcard(pattern, value string) bool {
	pIdx := 0
	vIdx := 0
	starIdx := -1
	matchIdx := 0
	for vIdx < len(value) {
		if pIdx < len(pattern) && (pattern[pIdx] == value[vIdx] || pattern[pIdx] == '?') {
			pIdx++
			vIdx++
			continue
		}
		if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = vIdx
			pIdx++
			continue
		}
		if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			vIdx = matchIdx
			continue
		}
		return false
	}
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

func StableKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
