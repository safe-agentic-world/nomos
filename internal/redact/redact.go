package redact

import (
	"errors"
	"regexp"
)

type Redactor struct {
	patterns []*regexp.Regexp
}

func DefaultRedactor() *Redactor {
	return &Redactor{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)authorization:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)proxy-authorization:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)cookie:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)set-cookie:\s*[^\r\n]+`),
			regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`),
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*-----END [A-Z ]+-----`),
		},
	}
}

func NewRedactor(customPatterns []string) (*Redactor, error) {
	redactor := DefaultRedactor()
	for _, pattern := range customPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.New("invalid redaction pattern")
		}
		redactor.patterns = append(redactor.patterns, re)
	}
	return redactor, nil
}

func (r *Redactor) RedactText(text string) string {
	redacted := text
	for _, pattern := range r.patterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED]")
	}
	return redacted
}

func (r *Redactor) RedactBytes(payload []byte) []byte {
	return []byte(r.RedactText(string(payload)))
}
