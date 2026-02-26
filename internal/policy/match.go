package policy

import (
	"sort"
	"strings"
)

func matchField(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == value
}

func matchList(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, item := range allowed {
		if item == "*" || item == value {
			return true
		}
	}
	return false
}

func matchRisk(required []string, available map[string]bool) bool {
	for _, flag := range required {
		if !available[strings.ToLower(flag)] {
			return false
		}
	}
	return true
}

func mergeObligations(rules []Rule, decision string) map[string]any {
	merged := map[string]any{}
	ids := make([]string, 0)
	ruleMap := map[string]Rule{}
	for _, rule := range rules {
		if rule.Decision != decision {
			continue
		}
		if len(rule.Obligations) == 0 {
			continue
		}
		ids = append(ids, rule.ID)
		ruleMap[rule.ID] = rule
	}
	sort.Strings(ids)
	for _, id := range ids {
		rule := ruleMap[id]
		for key, value := range rule.Obligations {
			if _, exists := merged[key]; !exists {
				merged[key] = value
			}
		}
	}
	return merged
}
