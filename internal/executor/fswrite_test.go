package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFSWriteContainment(t *testing.T) {
	dir := t.TempDir()
	writer := NewFSWriter(dir, 32)
	_, err := writer.Write("file://workspace/../secret.txt", []byte("x"))
	if err == nil {
		t.Fatal("expected traversal error")
	}
	_, err = writer.Write("file://workspace/ok.txt", []byte("ok"))
	if err != nil {
		t.Fatalf("expected write ok, got %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "ok.txt"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(content) != "ok" {
		t.Fatalf("unexpected content: %s", content)
	}
}

func TestFSWriteMaxBytes(t *testing.T) {
	dir := t.TempDir()
	writer := NewFSWriter(dir, 1)
	_, err := writer.Write("file://workspace/ok.txt", []byte("too long"))
	if err == nil {
		t.Fatal("expected max bytes error")
	}
}
