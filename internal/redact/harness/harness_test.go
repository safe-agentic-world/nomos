package harness

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

type secretsCorpusEntry struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	Expected  string `json:"expected"`
	Forbidden string `json:"forbidden"`
}

func TestHarnessNoLeakAcrossSurfaces(t *testing.T) {
	entries := loadSecretsCorpus(t)
	redactor := redact.DefaultRedactor()
	for _, entry := range entries {
		result, err := Run(redactor, entry.Input)
		if err != nil {
			t.Fatalf("%s: run harness: %v", entry.Name, err)
		}
		if result.Stdout != entry.Expected || result.Stderr != entry.Expected || result.HTTPBody != entry.Expected || result.HTTPHeaders != entry.Expected {
			t.Fatalf("%s: expected core surfaces to equal %q, got %+v", entry.Name, entry.Expected, result)
		}
		for _, stream := range Streams(result) {
			if entry.Forbidden != "" && strings.Contains(stream, entry.Forbidden) {
				t.Fatalf("%s: forbidden substring leaked in stream %q", entry.Name, stream)
			}
		}
	}
}

func loadSecretsCorpus(t *testing.T) []secretsCorpusEntry {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "redaction", "secrets_corpus.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open secrets corpus: %v", err)
	}
	defer file.Close()
	var entries []secretsCorpusEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry secretsCorpusEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse secrets corpus: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan secrets corpus: %v", err)
	}
	return entries
}
