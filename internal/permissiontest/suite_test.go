package permissiontest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSuite = `{"schema_version":"v1","identity":{"principal":"developer","agent":"demo","environment":"dev"},"cases":[{"name":"draft","action":{"action_type":"email.draft","resource":"inbox://local/draft","params":{}},"expect":"ALLOW","rules":["draft"]}]}`

func TestSuiteDeterministicAndDetectsRegression(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "policy.yaml")
	suite := filepath.Join(dir, "suite.json")
	write(t, bundle, "version: v1\nrules:\n  - id: draft\n    action_type: email.draft\n    resource: inbox://local/*\n    decision: ALLOW\n")
	write(t, suite, testSuite)
	a, err := Run(suite, bundle)
	if err != nil || a.Passed != 1 || a.Failed != 0 {
		t.Fatalf("report: %+v, %v", a, err)
	}
	b, err := Run(suite, bundle)
	if err != nil || a.PolicyBundleHash != b.PolicyBundleHash {
		t.Fatal("non-deterministic policy hash")
	}
	write(t, suite, strings.Replace(testSuite, `"expect":"ALLOW"`, `"expect":"DENY"`, 1))
	r, err := Run(suite, bundle)
	if err != nil || r.Failed != 1 {
		t.Fatalf("missed changed decision: %+v %v", r, err)
	}
	write(t, suite, strings.Replace(testSuite, `"rules":["draft"]`, `"rules":[]`, 1))
	r, err = Run(suite, bundle)
	if err != nil || r.Failed != 1 {
		t.Fatal("missed changed rule provenance")
	}
}

func TestSuiteRejectsInvalidCasesInsteadOfTreatingErrorsAsDenials(t *testing.T) {
	dir := t.TempDir()
	bundle, suite := filepath.Join(dir, "policy.json"), filepath.Join(dir, "suite.json")
	write(t, bundle, `{"version":"v1","rules":[]}`)
	for name, data := range map[string]string{
		"unknown field":       strings.Replace(testSuite, `"name":"draft"`, `"name":"draft","typo":true`, 1),
		"trailing data":       testSuite + `{}`,
		"invalid expectation": strings.Replace(testSuite, `"expect":"ALLOW"`, `"expect":"allow"`, 1),
		"invalid action":      strings.Replace(testSuite, `email.draft`, `BadAction`, 1),
		"empty identity":      strings.Replace(testSuite, `"principal":"developer"`, `"principal":""`, 1),
		"wrong version":       strings.Replace(testSuite, `"schema_version":"v1"`, `"schema_version":"v2"`, 1),
		"empty name":          strings.Replace(testSuite, `"name":"draft"`, `"name":""`, 1),
		"invalid params":      strings.Replace(testSuite, `"params":{}`, `"params":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			write(t, suite, data)
			if _, err := Run(suite, bundle); err == nil {
				t.Fatal("invalid suite accepted")
			}
		})
	}
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
