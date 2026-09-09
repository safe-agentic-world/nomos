package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPermissionSuiteCLI(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "local-inbox")
	args := []string{"--suite", filepath.Join(root, "permissions.json"), "--bundle", filepath.Join(root, "policy.yaml")}
	var out, stderr bytes.Buffer
	if code := runPermissionTests(args, &out, &stderr); code != 0 {
		t.Fatalf("code %d: %s", code, &stderr)
	}
	if !strings.Contains(out.String(), "6 passed, 0 failed") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := runPermissionTests(append(args, "--format", "json"), &out, &stderr); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("invalid JSON output: %s", &out)
	}
	data, err := os.ReadFile(filepath.Join(root, "permissions.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "regression.json")
	if err := os.WriteFile(bad, []byte(strings.Replace(string(data), `"expect": "ALLOW"`, `"expect": "DENY"`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	args[1] = bad
	if code := runPermissionTests(args, &out, &stderr); code != 1 {
		t.Fatalf("regression should exit 1, got %d", code)
	}
	for _, invalid := range [][]string{nil, {"--format", "xml"}, {"--help", "--bad"}, {"--suite", "missing", "--bundle", "missing"}} {
		code := runPermissionTests(invalid, &out, &stderr)
		if len(invalid) > 0 && invalid[0] == "--help" {
			if code != 0 {
				t.Fatal(code)
			}
			continue
		}
		if code != 2 {
			t.Fatalf("invalid input should exit 2, got %d", code)
		}
	}
}
