package harness

import (
	"encoding/json"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

type Result struct {
	Stdout      string
	Stderr      string
	HTTPHeaders string
	HTTPBody    string
	PatchDiff   string
	AuditField  string
}

func Run(redactor *redact.Redactor, input string) (Result, error) {
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	auditPayload, err := json.Marshal(map[string]any{
		"field": input,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		Stdout:      redactor.RedactText(input),
		Stderr:      redactor.RedactText(input),
		HTTPHeaders: redactor.RedactText(input),
		HTTPBody:    redactor.RedactText(input),
		PatchDiff:   redactor.RedactText("@@\n+" + input + "\n"),
		AuditField:  string(redactor.RedactBytes(auditPayload)),
	}, nil
}

func Streams(result Result) []string {
	return []string{
		result.Stdout,
		result.Stderr,
		result.HTTPHeaders,
		result.HTTPBody,
		result.PatchDiff,
		result.AuditField,
	}
}
