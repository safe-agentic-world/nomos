package policy

import (
	"fmt"
	"strings"
)

// LintWarning is an authoring problem in a bundle that does not make it
// invalid but makes a rule weaker than it reads.
type LintWarning struct {
	RuleID  string `json:"rule_id"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// LintCodeExactLengthFlagPattern marks an argv pattern that ends with a flag
// and has no trailing "**": it matches only an argv of exactly that length,
// so `["git", "push", "--force"]` never fires on `git push --force origin
// main`, the most common authoring mistake found in the incident research.
const LintCodeExactLengthFlagPattern = "exact_length_flag_pattern"

// LintBundle reports authoring warnings for a bundle. It never changes a
// decision; callers print the warnings next to test or explain output.
func LintBundle(bundle Bundle) []LintWarning {
	var out []LintWarning
	for _, rule := range bundle.Rules {
		if rule.ExecMatch == nil {
			continue
		}
		extended := map[string]bool{}
		for _, pattern := range rule.ExecMatch.ArgvPatterns {
			if n := len(pattern); n >= 2 && pattern[n-1] == "**" {
				extended[strings.Join(pattern[:n-1], "\x00")] = true
			}
		}
		for idx, pattern := range rule.ExecMatch.ArgvPatterns {
			n := len(pattern)
			if n < 2 {
				continue
			}
			last := pattern[n-1]
			if !strings.HasPrefix(last, "-") || strings.ContainsAny(last, "*?") {
				continue
			}
			if extended[strings.Join(pattern, "\x00")] {
				continue
			}
			out = append(out, LintWarning{
				RuleID: rule.ID,
				Code:   LintCodeExactLengthFlagPattern,
				Message: fmt.Sprintf("rule %s exec_match.argv_patterns[%d] %s ends with the flag %q and has no trailing \"**\": it matches only an argv of exactly %d tokens, so the same command with any further argument is not matched; append \"**\" to gate the command family",
					rule.ID, idx, formatPattern(pattern), last, n),
			})
		}
	}
	return out
}

func formatPattern(pattern []string) string {
	quoted := make([]string, 0, len(pattern))
	for _, token := range pattern {
		quoted = append(quoted, fmt.Sprintf("%q", token))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
