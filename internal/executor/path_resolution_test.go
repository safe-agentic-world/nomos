package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWorkspacePathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	linkPath := filepath.Join(root, "link")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlink unsupported in test environment: %v", err)
	}
	_, err := resolveWorkspacePath(root, "file://workspace/link/secret.txt")
	if err == nil {
		t.Fatal("expected symlink escape rejection")
	}
	if err.Error() != "path escape detected" {
		t.Fatalf("expected path escape detected, got %v", err)
	}
}
