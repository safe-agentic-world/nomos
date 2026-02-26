package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type FSWriter struct {
	workspaceRoot string
	maxBytes      int
}

type WriteResult struct {
	BytesWritten int
}

func NewFSWriter(workspaceRoot string, maxBytes int) *FSWriter {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return &FSWriter{
		workspaceRoot: workspaceRoot,
		maxBytes:      maxBytes,
	}
}

func (w *FSWriter) Write(resource string, content []byte) (WriteResult, error) {
	if len(content) > w.maxBytes {
		return WriteResult{}, errors.New("content exceeds max bytes")
	}
	path, err := resolveWorkspacePath(w.workspaceRoot, resource)
	if err != nil {
		return WriteResult{}, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return WriteResult{}, err
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{BytesWritten: len(content)}, nil
}

func resolveWorkspacePath(root, resource string) (string, error) {
	if !strings.HasPrefix(resource, "file://workspace/") {
		return "", errors.New("unsupported resource")
	}
	rel := strings.TrimPrefix(resource, "file://workspace/")
	rel = filepath.FromSlash(rel)
	cleanRel := filepath.Clean(rel)
	if strings.HasPrefix(cleanRel, "..") {
		return "", errors.New("path traversal detected")
	}
	fullPath := filepath.Join(root, cleanRel)
	relCheck, err := filepath.Rel(root, fullPath)
	if err != nil {
		return "", errors.New("path escape detected")
	}
	if strings.HasPrefix(relCheck, "..") {
		return "", errors.New("path escape detected")
	}
	return fullPath, nil
}
