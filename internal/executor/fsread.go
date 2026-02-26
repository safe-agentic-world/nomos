package executor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type FSReader struct {
	workspaceRoot string
	maxBytes      int
	maxLines      int
}

type ReadResult struct {
	Content   string
	BytesRead int
	LinesRead int
	Truncated bool
}

func NewFSReader(workspaceRoot string, maxBytes, maxLines int) *FSReader {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if maxLines <= 0 {
		maxLines = 200
	}
	return &FSReader{
		workspaceRoot: workspaceRoot,
		maxBytes:      maxBytes,
		maxLines:      maxLines,
	}
}

func (r *FSReader) Read(resource string) (ReadResult, error) {
	fullPath, err := resolveWorkspacePath(r.workspaceRoot, resource)
	if err != nil {
		return ReadResult{}, err
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return ReadResult{}, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var builder strings.Builder
	bytesRead := 0
	linesRead := 0
	truncated := false
	for {
		if linesRead >= r.maxLines || bytesRead >= r.maxBytes {
			truncated = true
			break
		}
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			remaining := r.maxBytes - bytesRead
			if remaining <= 0 {
				truncated = true
				break
			}
			if len(line) > remaining {
				line = line[:remaining]
				truncated = true
			}
			builder.WriteString(line)
			bytesRead += len(line)
			linesRead++
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return ReadResult{}, fmt.Errorf("read file: %w", err)
		}
		if truncated {
			break
		}
	}

	return ReadResult{
		Content:   builder.String(),
		BytesRead: bytesRead,
		LinesRead: linesRead,
		Truncated: truncated,
	}, nil
}
