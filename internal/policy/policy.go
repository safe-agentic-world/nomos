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

type ExplainDetails struct {
	Decision               Decision
	DenyRules              []DeniedRuleExplanation
	AllowRuleIDs           []string
	RequireApprovalRuleIDs []string
	ObligationsPreview     map[string]any
}

type DeniedRuleExplanation struct {
	RuleID            string
	ReasonCode        string
	MatchedConditions map[string]bool
}

type Engine struct {
	bundle Bundle
}

func NewEngine(bundle Bundle) *Engine {
	return &Engine{bundle: bundle}
}

func (e *Engine) Evaluate(action normalize.NormalizedAction) Decision {
	return e.Explain(action).Decision
}

func (e *Engine) Explain(action normalize.NormalizedAction) ExplainDetails {
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
	denyIDs := make([]string, 0)
	requireIDs := make([]string, 0)
	allowIDs := make([]string, 0)
	denyExplanations := make([]DeniedRuleExplanation, 0)
	denyObligations := mergeObligations(matched, DecisionDeny)
	requireObligations := mergeObligations(matched, DecisionRequireApproval)
	allowObligations := mergeObligations(matched, DecisionAllow)
	if len(matched) == 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:         DecisionDeny,
				ReasonCode:       "deny_by_default",
				MatchedRuleIDs:   []string{},
				Obligations:      map[string]any{},
				PolicyBundleHash: e.bundle.Hash,
			},
			DenyRules:              []DeniedRuleExplanation{},
			AllowRuleIDs:           []string{},
			RequireApprovalRuleIDs: []string{},
			ObligationsPreview:     map[string]any{},
		}
	}
	for _, rule := range matched {
		if rule.Decision == DecisionDeny {
			denyIDs = append(denyIDs, rule.ID)
			denyExplanations = append(denyExplanations, DeniedRuleExplanation{
				RuleID:     rule.ID,
				ReasonCode: "deny_by_rule",
				MatchedConditions: map[string]bool{
					"action_type": true,
					"resource":    true,
					"principal":   true,
					"agent":       true,
					"environment": true,
					"risk_flags":  true,
				},
			})
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
	sort.Slice(denyExplanations, func(i, j int) bool {
		return denyExplanations[i].RuleID < denyExplanations[j].RuleID
	})
	if len(denyIDs) > 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:         DecisionDeny,
				ReasonCode:       "deny_by_rule",
				MatchedRuleIDs:   denyIDs,
				Obligations:      denyObligations,
				PolicyBundleHash: e.bundle.Hash,
			},
			DenyRules:              denyExplanations,
			AllowRuleIDs:           append([]string{}, allowIDs...),
			RequireApprovalRuleIDs: append([]string{}, requireIDs...),
			ObligationsPreview:     copyObligations(allowObligations),
		}
	}
	if len(requireIDs) > 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:         DecisionRequireApproval,
				ReasonCode:       "require_approval_by_rule",
				MatchedRuleIDs:   requireIDs,
				Obligations:      requireObligations,
				PolicyBundleHash: e.bundle.Hash,
			},
			DenyRules:              []DeniedRuleExplanation{},
			AllowRuleIDs:           append([]string{}, allowIDs...),
			RequireApprovalRuleIDs: append([]string{}, requireIDs...),
			ObligationsPreview:     copyObligations(requireObligations),
		}
	}
	return ExplainDetails{
		Decision: Decision{
			Decision:         DecisionAllow,
			ReasonCode:       "allow_by_rule",
			MatchedRuleIDs:   allowIDs,
			Obligations:      allowObligations,
			PolicyBundleHash: e.bundle.Hash,
		},
		DenyRules:              []DeniedRuleExplanation{},
		AllowRuleIDs:           append([]string{}, allowIDs...),
		RequireApprovalRuleIDs: []string{},
		ObligationsPreview:     copyObligations(allowObligations),
	}
}

func copyObligations(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
