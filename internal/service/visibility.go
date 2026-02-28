package service

import (
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
)

func riskVisibility(normalized normalize.NormalizedAction) (string, []string) {
	flags := policy.ComputeRiskFlags(normalized)
	list := make([]string, 0, len(flags))
	for k, v := range flags {
		if v {
			list = append(list, k)
		}
	}
	sort.Strings(list)
	level := "low"
	for _, f := range list {
		if f == "risk.exec" || f == "risk.secrets" || f == "risk.high_fanout" {
			return "high", list
		}
		if f == "risk.net" || f == "risk.write" || f == "risk.large_io" {
			level = "medium"
		}
	}
	return level, list
}

func visibilityModes(obligations map[string]any, configuredSandbox string, actionType string) (string, string) {
	sandboxMode := "none"
	if selected, err := sandbox.SelectProfile(obligations, configuredSandbox); err == nil {
		sandboxMode = selected
	}
	networkMode := "deny"
	if actionType == "net.http_request" {
		networkMode = "open"
	}
	if obligations != nil {
		if list, ok := obligations["net_allowlist"]; ok {
			if arr, ok := list.([]any); ok && len(arr) > 0 {
				networkMode = "allowlist"
			}
		}
	}
	return sandboxMode, networkMode
}

func credentialLeaseIDs(obligations map[string]any) []string {
	if obligations == nil {
		return []string{}
	}
	raw, ok := obligations["credential_lease_ids"]
	if !ok {
		return []string{}
	}
	arr, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func actionSummary(actionType, resource string) string {
	return strings.TrimSpace(actionType) + " " + strings.TrimSpace(resource)
}
