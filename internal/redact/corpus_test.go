package redact

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type secretsCorpusEntry struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	Expected  string `json:"expected"`
	Forbidden string `json:"forbidden"`
}

type falsePositiveEntry struct {
	Name     string `json:"name"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

func TestSecretsCorpusExactAndDeterministic(t *testing.T) {
	entries := loadSecretsCorpus(t)
	if len(entries) < 150 {
		t.Fatalf("expected at least 150 secret corpus entries, got %d", len(entries))
	}
	redactor := DefaultRedactor()
	for _, entry := range entries {
		got1 := redactor.RedactText(entry.Input)
		got2 := redactor.RedactText(entry.Input)
		if got1 != entry.Expected || got2 != entry.Expected {
			t.Fatalf("%s: expected %q, got %q and %q", entry.Name, entry.Expected, got1, got2)
		}
		if entry.Forbidden != "" && strings.Contains(got1, entry.Forbidden) {
			t.Fatalf("%s: output still contains forbidden substring", entry.Name)
		}
	}
}

func TestFalsePositiveCorpusPreserved(t *testing.T) {
	entries := loadFalsePositiveCorpus(t)
	if len(entries) == 0 {
		t.Fatal("expected false positive corpus entries")
	}
	redactor := DefaultRedactor()
	for _, entry := range entries {
		got1 := redactor.RedactText(entry.Input)
		got2 := redactor.RedactText(entry.Input)
		if got1 != entry.Expected || got2 != entry.Expected {
			t.Fatalf("%s: expected %q, got %q and %q", entry.Name, entry.Expected, got1, got2)
		}
	}
}

func loadSecretsCorpus(t *testing.T) []secretsCorpusEntry {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "redaction", "secrets_corpus.jsonl")
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
		if entry.Name == "" || entry.Input == "" {
			t.Fatalf("invalid secrets corpus entry: %+v", entry)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan secrets corpus: %v", err)
	}
	return entries
}

func loadFalsePositiveCorpus(t *testing.T) []falsePositiveEntry {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "redaction", "false_positive_corpus.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open false positive corpus: %v", err)
	}
	defer file.Close()
	var entries []falsePositiveEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry falsePositiveEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse false positive corpus: %v", err)
		}
		if entry.Name == "" {
			t.Fatalf("invalid false positive corpus entry: %+v", entry)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan false positive corpus: %v", err)
	}
	return entries
}
