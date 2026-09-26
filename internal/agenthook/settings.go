package agenthook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMatcher lists the built-in Claude Code tools the hook governs by
// default. MCP tools (`mcp__server__tool`) are opt-in because a default-deny
// bundle would turn every MCP call into a prompt.
const DefaultMatcher = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch"

// DefaultTimeoutSeconds bounds the hook. Claude Code treats a timed-out hook as
// non-blocking, so the timeout is short and the hook does no network I/O.
const DefaultTimeoutSeconds = 10

const hookCommandMarker = "nomos hook claude-code"

// SettingsSnippet returns the `hooks` block that registers the hook.
func SettingsSnippet(command, matcher string, timeoutSeconds int) map[string]any {
	if strings.TrimSpace(matcher) == "" {
		matcher = DefaultMatcher
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultTimeoutSeconds
	}
	return map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": matcher,
					"hooks": []any{
						map[string]any{
							"type":    "command",
							"command": command,
							"timeout": timeoutSeconds,
						},
					},
				},
			},
		},
	}
}

// InstallHook merges the hook registration into a Claude Code settings file,
// creating the file when needed and leaving every other key untouched. It
// reports false when a Nomos hook entry is already present.
func InstallHook(settingsPath, command, matcher string, timeoutSeconds int) (bool, error) {
	if strings.TrimSpace(command) == "" || !strings.Contains(command, hookCommandMarker) {
		return false, fmt.Errorf("hook command must invoke %q", hookCommandMarker)
	}
	return installHooks(settingsPath, hookCommandMarker, SettingsSnippet(command, matcher, timeoutSeconds))
}

// installHooks merges snippet["hooks"] into the hooks object of a JSON
// settings file, event by event. An event that already holds a hook whose
// command contains marker is left alone; every other key in the file is
// preserved. It reports whether the file changed.
func installHooks(settingsPath, marker string, snippet map[string]any) (bool, error) {
	settingsPath = strings.TrimSpace(settingsPath)
	if settingsPath == "" {
		return false, errors.New("settings path is required")
	}
	settings := map[string]any{}
	data, err := os.ReadFile(settingsPath)
	switch {
	case err == nil:
		if len(bytes.TrimSpace(data)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			if err := dec.Decode(&settings); err != nil {
				return false, fmt.Errorf("parse %s: %w", settingsPath, err)
			}
		}
	case os.IsNotExist(err):
	default:
		return false, fmt.Errorf("read %s: %w", settingsPath, err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		if _, present := settings["hooks"]; present {
			return false, fmt.Errorf("%s: hooks is not an object", settingsPath)
		}
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	wanted, _ := snippet["hooks"].(map[string]any)
	changed := false
	for event, newEntriesAny := range wanted {
		newEntries, _ := newEntriesAny.([]any)
		entries, ok := hooks[event].([]any)
		if !ok {
			if _, present := hooks[event]; present {
				return false, fmt.Errorf("%s: hooks.%s is not an array", settingsPath, event)
			}
			entries = []any{}
		}
		if hasMarkedHook(entries, marker) {
			continue
		}
		hooks[event] = append(entries, newEntries...)
		changed = true
	}
	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return false, fmt.Errorf("create settings directory: %w", err)
	}
	if err := os.WriteFile(settingsPath, append(out, '\n'), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", settingsPath, err)
	}
	return true, nil
}

func hasMarkedHook(entries []any, marker string) bool {
	for _, entry := range entries {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := entryMap["hooks"].([]any)
		for _, h := range inner {
			hMap, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := hMap["command"].(string); strings.Contains(cmd, marker) {
				return true
			}
		}
	}
	return false
}
