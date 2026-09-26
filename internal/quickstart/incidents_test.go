package quickstart

import (
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/permissiontest"
)

// TestIncidentSuitesPassAgainstDefaultProfiles keeps the checked-in incident
// regression suites green against the canonical profiles in /profiles.
func TestIncidentSuitesPassAgainstDefaultProfiles(t *testing.T) {
	root := repoRoot(t)
	for _, name := range []string{"safe-dev", "ci-strict", "prod-locked"} {
		suite := filepath.Join(root, "examples", "incidents", name+".permissions.json")
		bundle := filepath.Join(root, "profiles", name+".yaml")
		report, err := permissiontest.Run(suite, bundle)
		if err != nil {
			t.Fatalf("%s: run suite: %v", name, err)
		}
		if report.Failed != 0 {
			for _, result := range report.Results {
				if !result.Passed {
					t.Errorf("%s: case %q expected %s got %s (rules %v, expected rules %v)", name, result.Name, result.Expected, result.Actual, result.MatchedRules, result.ExpectedRules)
				}
			}
			t.Fatalf("%s: %d of %d incident cases failed", name, report.Failed, report.Passed+report.Failed)
		}
		if report.Passed < 20 {
			t.Fatalf("%s: suite has only %d cases; incident coverage must not shrink", name, report.Passed)
		}
	}
}
