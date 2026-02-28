package policy

import (
	"sort"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

const (
	DecisionAllow           = "ALLOW"
	DecisionDeny            = "DENY"
	DecisionRequireApproval = "REQUIRE_APPROVAL"
)

type Decision struct {
	Decision         string
	ReasonCode       string
	Message          string
	MatchedRuleIDs   []string
	Obligations      map[string]any
	PolicyBundleHash string
}

type Engine struct {
	bundle Bundle
}

func NewEngine(bundle Bundle) *Engine {
	return &Engine{bundle: bundle}
}

func (e *Engine) Evaluate(action normalize.NormalizedAction) Decision {
	risk := ComputeRiskFlags(action)
	matched := make([]Rule, 0)
	for _, rule := range e.bundle.Rules {
		if !matchField(rule.ActionType, action.ActionType) {
			continue
		}
		ok, err := normalize.MatchPattern(rule.Resource, action.Resource)
		if err != nil || !ok {
			continue
		}
		if !matchList(rule.Principals, action.Principal) {
			continue
		}
		if !matchList(rule.Agents, action.Agent) {
			continue
		}
		if !matchList(rule.Environments, action.Environment) {
			continue
		}
		if !matchRisk(rule.RiskFlags, risk) {
			continue
		}
		matched = append(matched, rule)
	}
	if len(matched) == 0 {
		return Decision{
			Decision:         DecisionDeny,
			ReasonCode:       "deny_by_default",
			MatchedRuleIDs:   []string{},
			Obligations:      map[string]any{},
			PolicyBundleHash: e.bundle.Hash,
		}
	}
	denyIDs := make([]string, 0)
	requireIDs := make([]string, 0)
	allowIDs := make([]string, 0)
	denyObligations := mergeObligations(matched, DecisionDeny)
	requireObligations := mergeObligations(matched, DecisionRequireApproval)
	allowObligations := mergeObligations(matched, DecisionAllow)
	for _, rule := range matched {
		if rule.Decision == DecisionDeny {
			denyIDs = append(denyIDs, rule.ID)
		}
		if rule.Decision == DecisionRequireApproval {
			requireIDs = append(requireIDs, rule.ID)
		}
		if rule.Decision == DecisionAllow {
			allowIDs = append(allowIDs, rule.ID)
		}
	}
	sort.Strings(denyIDs)
	sort.Strings(requireIDs)
	sort.Strings(allowIDs)
	if len(denyIDs) > 0 {
		return Decision{
			Decision:         DecisionDeny,
			ReasonCode:       "deny_by_rule",
			MatchedRuleIDs:   denyIDs,
			Obligations:      denyObligations,
			PolicyBundleHash: e.bundle.Hash,
		}
	}
	if len(requireIDs) > 0 {
		return Decision{
			Decision:         DecisionRequireApproval,
			ReasonCode:       "require_approval_by_rule",
			MatchedRuleIDs:   requireIDs,
			Obligations:      requireObligations,
			PolicyBundleHash: e.bundle.Hash,
		}
	}
	return Decision{
		Decision:         DecisionAllow,
		ReasonCode:       "allow_by_rule",
		MatchedRuleIDs:   allowIDs,
		Obligations:      allowObligations,
		PolicyBundleHash: e.bundle.Hash,
	}
}
