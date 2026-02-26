package redact

import (
	"strings"
	"testing"
)

func TestRedactionPatterns(t *testing.T) {
	redactor := DefaultRedactor()
	cases := []string{
		"Authorization: Bearer secret\n",
		"Cookie: session=abc\n",
		"AKIA1234567890ABCDEF",
		"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
	}
	for _, input := range cases {
		output := redactor.RedactText(input)
		if output == input {
			t.Fatalf("expected redaction for %q", input)
		}
		if strings.Contains(output, "secret") || strings.Contains(output, "AKIA") || strings.Contains(output, "PRIVATE KEY") {
			t.Fatalf("expected sensitive data to be redacted for %q", input)
		}
	}
}
