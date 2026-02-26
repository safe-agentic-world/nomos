package executor

import (
	"errors"
)

type PatchApplier struct {
	writer *FSWriter
}

type PatchResult struct {
	BytesWritten int
}

func NewPatchApplier(workspaceRoot string, maxBytes int) *PatchApplier {
	return &PatchApplier{
		writer: NewFSWriter(workspaceRoot, maxBytes),
	}
}

func (p *PatchApplier) Apply(path string, content []byte) (PatchResult, error) {
	if path == "" {
		return PatchResult{}, errors.New("path is required")
	}
	result, err := p.writer.Write("file://workspace/"+path, content)
	if err != nil {
		return PatchResult{}, err
	}
	return PatchResult{BytesWritten: result.BytesWritten}, nil
}
