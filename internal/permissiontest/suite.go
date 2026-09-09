// Package permissiontest runs deterministic, side-effect-free policy regressions.
package permissiontest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type Suite struct {
	SchemaVersion string `json:"schema_version"`
	Identity      struct {
		Principal   string `json:"principal"`
		Agent       string `json:"agent"`
		Environment string `json:"environment"`
	} `json:"identity"`
	Cases []Case `json:"cases"`
}

type Case struct {
	Name   string `json:"name"`
	Action struct {
		ActionType string          `json:"action_type"`
		Resource   string          `json:"resource"`
		Params     json.RawMessage `json:"params"`
	} `json:"action"`
	Expect string    `json:"expect"`
	Rules  *[]string `json:"rules,omitempty"`
}

type Result struct {
	Name          string    `json:"name"`
	Expected      string    `json:"expected"`
	Actual        string    `json:"actual"`
	MatchedRules  []string  `json:"matched_rules"`
	ExpectedRules *[]string `json:"expected_rules,omitempty"`
	Passed        bool      `json:"passed"`
}

type Report struct {
	PolicyBundleHash string   `json:"policy_bundle_hash"`
	Passed           int      `json:"passed"`
	Failed           int      `json:"failed"`
	Results          []Result `json:"results"`
}

// Run evaluates policy only. It never starts a gateway, agent, or executor.
func Run(suitePath, bundlePath string) (Report, error) {
	data, err := os.ReadFile(suitePath)
	if err != nil {
		return Report{}, err
	}
	var suite Suite
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&suite); err != nil {
		return Report{}, fmt.Errorf("decode suite: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Report{}, errors.New("suite has trailing data")
	}
	if suite.SchemaVersion != "v1" || len(suite.Cases) == 0 {
		return Report{}, errors.New("suite requires schema_version v1 and at least one case")
	}
	id := identity.VerifiedIdentity{Principal: suite.Identity.Principal, Agent: suite.Identity.Agent, Environment: suite.Identity.Environment}
	if strings.TrimSpace(id.Principal) == "" || strings.TrimSpace(id.Agent) == "" || strings.TrimSpace(id.Environment) == "" {
		return Report{}, errors.New("suite identity requires principal, agent, and environment")
	}
	bundle, err := policy.LoadBundle(bundlePath)
	if err != nil {
		return Report{}, err
	}
	engine := policy.NewEngine(bundle)
	report := Report{PolicyBundleHash: bundle.Hash, Results: []Result{}}
	names := map[string]bool{}
	for i, c := range suite.Cases {
		if strings.TrimSpace(c.Name) == "" || names[c.Name] {
			return Report{}, fmt.Errorf("case %d has an empty or duplicate name", i+1)
		}
		names[c.Name] = true
		if c.Expect != policy.DecisionAllow && c.Expect != policy.DecisionDeny && c.Expect != policy.DecisionRequireApproval {
			return Report{}, fmt.Errorf("case %q: invalid expect %q", c.Name, c.Expect)
		}
		params := c.Action.Params
		if len(params) == 0 {
			params = json.RawMessage(`{}`)
		}
		request, err := json.Marshal(map[string]any{
			"schema_version": "v1", "action_id": fmt.Sprintf("test-%d", i+1), "trace_id": "permission-test",
			"action_type": c.Action.ActionType, "resource": c.Action.Resource, "params": params,
			"context": map[string]any{"extensions": map[string]any{}},
		})
		if err != nil {
			return Report{}, fmt.Errorf("case %q: %w", c.Name, err)
		}
		req, err := action.DecodeActionRequestBytes(request)
		if err != nil {
			return Report{}, fmt.Errorf("case %q: %w", c.Name, err)
		}
		act, err := action.ToAction(req, id)
		if err != nil {
			return Report{}, fmt.Errorf("case %q: %w", c.Name, err)
		}
		norm, err := normalize.Action(act)
		if err != nil {
			return Report{}, fmt.Errorf("case %q: %w", c.Name, err)
		}
		decision := engine.Evaluate(norm)
		result := Result{Name: c.Name, Expected: c.Expect, Actual: decision.Decision, MatchedRules: decision.MatchedRuleIDs, ExpectedRules: c.Rules, Passed: c.Expect == decision.Decision}
		if c.Rules != nil {
			result.Passed = result.Passed && sameRules(*c.Rules, decision.MatchedRuleIDs)
		}
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, result)
	}
	return report, nil
}

func sameRules(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
