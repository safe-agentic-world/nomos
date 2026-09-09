package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/safe-agentic-world/nomos/internal/permissiontest"
)

func runPermissionTests(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suite := fs.String("suite", "", "permission suite JSON path")
	bundle := fs.String("bundle", "", "policy bundle YAML or JSON path")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *suite == "" || *bundle == "" || fs.NArg() != 0 || (*format != "text" && *format != "json") {
		fmt.Fprintln(stderr, "usage: nomos test --suite <suite.json> --bundle <policy.yaml> [--format text|json]")
		return 2
	}
	report, err := permissiontest.Run(*suite, *bundle)
	if err != nil {
		fmt.Fprintf(stderr, "permission suite: %v\n", err)
		return 2
	}
	if *format == "json" {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		for _, result := range report.Results {
			status := "PASS"
			if !result.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(stdout, "%s %s: expected %s, got %s (rules: %v)\n", status, result.Name, result.Expected, result.Actual, result.MatchedRules)
			if !result.Passed && result.ExpectedRules != nil {
				fmt.Fprintf(stdout, "  expected rules: %v\n", *result.ExpectedRules)
			}
		}
		fmt.Fprintf(stdout, "%d passed, %d failed | policy %s\n", report.Passed, report.Failed, report.PolicyBundleHash)
	}
	if report.Failed != 0 {
		return 1
	}
	return 0
}
