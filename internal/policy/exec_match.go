package policy

import (
	"encoding/json"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type execParams struct {
	Argv []string `json:"argv"`
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
	for _, pattern := range rule.ExecMatch.ArgvPatterns {
		if matchArgvPattern(pattern, params.Argv) {
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

func matchArgvToken(pattern, token string) bool {
	return pattern == "*" || pattern == token
}
