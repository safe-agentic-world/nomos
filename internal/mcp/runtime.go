package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

type RuntimeOptions struct {
	LogLevel  string
	Quiet     bool
	LogFormat string
	ErrWriter io.Writer
}

type logLevel int

const (
	logLevelError logLevel = iota
	logLevelWarn
	logLevelInfo
	logLevelDebug
)

func ParseRuntimeOptions(options RuntimeOptions) (RuntimeOptions, error) {
	level := strings.TrimSpace(options.LogLevel)
	if level == "" {
		level = "info"
	}
	if _, err := parseLogLevel(level); err != nil {
		return RuntimeOptions{}, err
	}
	format := strings.TrimSpace(options.LogFormat)
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return RuntimeOptions{}, errors.New("invalid log format")
	}
	if options.ErrWriter == nil {
		options.ErrWriter = os.Stderr
	}
	return RuntimeOptions{
		LogLevel:  level,
		Quiet:     options.Quiet,
		LogFormat: format,
		ErrWriter: options.ErrWriter,
	}, nil
}

func parseLogLevel(value string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return logLevelError, nil
	case "warn":
		return logLevelWarn, nil
	case "info":
		return logLevelInfo, nil
	case "debug":
		return logLevelDebug, nil
	default:
		return logLevelInfo, errors.New("invalid log level")
	}
}

type runtimeLogger struct {
	mu       sync.Mutex
	level    logLevel
	format   string
	quiet    bool
	errOut   io.Writer
	redactor *redact.Redactor
	banner   bool
}

func newRuntimeLogger(options RuntimeOptions) (*runtimeLogger, error) {
	normalized, err := ParseRuntimeOptions(options)
	if err != nil {
		return nil, err
	}
	level, err := parseLogLevel(normalized.LogLevel)
	if err != nil {
		return nil, err
	}
	if normalized.Quiet {
		level = logLevelError
	}
	return &runtimeLogger{
		level:    level,
		format:   normalized.LogFormat,
		quiet:    normalized.Quiet,
		errOut:   normalized.ErrWriter,
		redactor: redact.DefaultRedactor(),
	}, nil
}

func (l *runtimeLogger) Error(message string) {
	l.write(logLevelError, "error", message)
}

func (l *runtimeLogger) Debug(message string) {
	l.write(logLevelDebug, "debug", message)
}

func (l *runtimeLogger) ReadyBanner(environment, policyBundleHash, engineVersion string, pid int) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.banner {
		return
	}
	line := fmt.Sprintf("[Nomos] MCP server ready (env=%s, policy_bundle_hash=%s, engine=%s, pid=%d)", environment, policyBundleHash, engineVersion, pid)
	l.writeLocked(line)
	l.banner = true
}

func (l *runtimeLogger) write(level logLevel, label, message string) {
	if level > l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.format == "json" {
		payload := map[string]string{
			"component": "nomos.mcp",
			"level":     label,
			"message":   message,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		l.writeLocked(string(data))
		return
	}
	l.writeLocked("[Nomos] " + strings.ToUpper(label) + " " + message)
}

func (l *runtimeLogger) writeLocked(line string) {
	redacted := l.redactor.RedactText(line)
	if !strings.HasSuffix(redacted, "\n") {
		redacted += "\n"
	}
	_, _ = io.WriteString(l.errOut, redacted)
}
