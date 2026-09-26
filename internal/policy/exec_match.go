package policy

import (
	"encoding/json"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type execParams struct {
	Argv    []string `json:"argv"`
	Program string   `json:"program"`
}

func matchExec(rule Rule, action normalize.NormalizedAction) bool {
	if rule.ExecMatch == nil {
		return true
	}
	if action.ActionType != "process.exec" {
		return false
	}
	params, ok := decodeExecParams(action.Params)
	if !ok || len(params.Argv) == 0 {
		return false
	}
	argvMatched := false
	for _, pattern := range rule.ExecMatch.ArgvPatterns {
		if matchArgvPattern(pattern, params.Argv) {
			argvMatched = true
			break
		}
	}
	if !argvMatched {
		return false
	}
	if len(rule.ExecMatch.ProgramPatterns) == 0 {
		return true
	}
	// A program pattern needs a program path: an action without one (a bare
	// name, an absolute path, or a caller that does not set it) never
	// matches such a rule.
	if params.Program == "" {
		return false
	}
	for _, pattern := range rule.ExecMatch.ProgramPatterns {
		if normalize.MatchWildcard(pattern, params.Program) {
			return true
		}
	}
	return false
}

func decodeExecParams(raw []byte) (execParams, bool) {
	var params execParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return execParams{}, false
	}
	if len(params.Argv) == 0 {
		return execParams{}, false
	}
	return params, true
}

func matchArgvPattern(pattern, argv []string) bool {
	return matchArgvSegments(pattern, argv)
}

func matchArgvSegments(pattern, argv []string) bool {
	if len(pattern) == 0 {
		return len(argv) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(argv); i++ {
			if matchArgvSegments(pattern[1:], argv[i:]) {
				return true
			}
		}
		return false
	}
	if len(argv) == 0 {
		return false
	}
	if !matchArgvToken(pattern[0], argv[0]) {
		return false
	}
	return matchArgvSegments(pattern[1:], argv[1:])
}

// matchArgvToken compares one argv token against one pattern token.
//
// A bare `*` matches any single token. A token containing `*` or `?` is a
// whole-token wildcard (for example `*.env*` matches `./config/.env.local`),
// which lets a rule match a sensitive path wherever it appears in argv:
// `["**", "*.pem", "**"]`. Tokens without wildcard characters match exactly.
func matchArgvToken(pattern, token string) bool {
	if pattern == "*" {
		return true
	}
	if strings.ContainsAny(pattern, `*?\`) {
		return normalize.MatchWildcard(pattern, token)
	}
	return pattern == token
}
