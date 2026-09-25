package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

const (
	fileChainTailBytes    = 256 << 10
	fileChainLockTimeout  = 3 * time.Second
	fileChainLockStale    = 30 * time.Second
	fileChainLockInterval = 20 * time.Millisecond
)

// FileChainRecorder appends redacted, hash-chained events to a JSONL file.
//
// Writer keeps the chain head in memory, which suits a long-lived gateway. A
// process that lives for a single decision (for example an editor hook that is
// invoked once per tool call) cannot do that, so this recorder re-reads the last
// event hash from the file on every write and extends that chain. Each stored
// line is self-verifying: the payload is redacted first and the hash is computed
// over the redacted, canonicalized line plus the previous hash, so
// VerifyFileChain can recompute every link from the file alone. Writes are
// serialized with a lock file beside the log.
type FileChainRecorder struct {
	path     string
	redactor *redact.Redactor
}

// NewFileChainRecorder returns a recorder that appends to path, creating the
// parent directory and the file on first use.
func NewFileChainRecorder(path string, redactor *redact.Redactor) (*FileChainRecorder, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("audit file path is required")
	}
	if redactor == nil {
		return nil, errors.New("redactor is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	return &FileChainRecorder{path: path, redactor: redactor}, nil
}

// Path returns the log file path.
func (r *FileChainRecorder) Path() string { return r.path }

// WriteEvent redacts, chains, and appends one event.
func (r *FileChainRecorder) WriteEvent(event Event) error {
	unlock, err := acquireFileLock(r.path+".lock", fileChainLockTimeout)
	if err != nil {
		return err
	}
	defer unlock()

	prevHash, err := lastEventHash(r.path)
	if err != nil {
		return err
	}
	line, err := chainedLine(event, prevHash, r.redactor)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return f.Sync()
}

func chainedLine(event Event, prevHash string, redactor *redact.Redactor) ([]byte, error) {
	event.PrevEventHash = ""
	event.EventHash = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	// Redact each string value on its own. Redacting the serialized line would
	// let a pattern that consumes to end-of-line (for example an Authorization
	// header) swallow the JSON that follows it and corrupt the record.
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	redactedJSON, err := json.Marshal(redactStrings(generic, redactor))
	if err != nil {
		return nil, err
	}
	var clean Event
	if err := json.Unmarshal(redactedJSON, &clean); err != nil {
		return nil, fmt.Errorf("redacted audit event is not decodable: %w", err)
	}
	hashed, err := withChainHash(clean, prevHash)
	if err != nil {
		return nil, err
	}
	line, err := json.Marshal(hashed)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

func redactStrings(value any, redactor *redact.Redactor) any {
	switch v := value.(type) {
	case string:
		return redactor.RedactText(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactStrings(item, redactor)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = redactStrings(item, redactor)
		}
		return out
	default:
		return value
	}
}

// VerifyFileChain recomputes every link of a JSONL chain written by
// FileChainRecorder and returns the number of verified events. It fails on the
// first event whose stored hash does not match its content and predecessor.
func VerifyFileChain(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	prevHash := ""
	for lineNo, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var stored Event
		if err := json.Unmarshal(line, &stored); err != nil {
			return count, fmt.Errorf("line %d: invalid audit event: %w", lineNo+1, err)
		}
		if stored.PrevEventHash != prevHash {
			return count, fmt.Errorf("line %d: prev_event_hash %q does not match previous event hash %q", lineNo+1, stored.PrevEventHash, prevHash)
		}
		expectedHash := stored.EventHash
		recomputed, err := withChainHash(stored, prevHash)
		if err != nil {
			return count, fmt.Errorf("line %d: %w", lineNo+1, err)
		}
		if recomputed.EventHash != expectedHash {
			return count, fmt.Errorf("line %d: event_hash mismatch", lineNo+1)
		}
		prevHash = expectedHash
		count++
	}
	return count, nil
}

func lastEventHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	if size == 0 {
		return "", nil
	}
	start := int64(0)
	if size > fileChainTailBytes {
		start = size - fileChainTailBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	tail, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	lines := bytes.Split(bytes.TrimRight(tail, "\n"), []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		if start > 0 && i == 0 {
			// The first line of a truncated tail may be partial; refuse to
			// guess rather than fork the chain.
			return "", errors.New("audit file tail is truncated; cannot determine chain head")
		}
		var stored struct {
			EventHash string `json:"event_hash"`
		}
		if err := json.Unmarshal(line, &stored); err != nil {
			return "", fmt.Errorf("last audit event is not decodable: %w", err)
		}
		if stored.EventHash == "" {
			return "", errors.New("last audit event has no event_hash")
		}
		return stored.EventHash, nil
	}
	return "", nil
}

// acquireFileLock creates lockPath exclusively, waiting up to timeout. A lock
// older than fileChainLockStale is treated as abandoned by a crashed process.
func acquireFileLock(lockPath string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create audit lock: %w", err)
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > fileChainLockStale {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("audit file is locked by another process")
		}
		time.Sleep(fileChainLockInterval)
	}
}

// HashCanonicalEvent is exported for tests and tooling that need the exact
// chain input of an event without a predecessor.
func HashCanonicalEvent(event Event) (string, error) {
	event.PrevEventHash = ""
	event.EventHash = ""
	payload, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	canonical, err := canonicaljson.Canonicalize(payload)
	if err != nil {
		return "", err
	}
	return canonicaljson.HashSHA256(canonical), nil
}
