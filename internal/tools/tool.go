package tools

import (
	"context"
	"encoding/json"
)

type Result struct {
	Content  json.RawMessage `json:"content"`
	Evidence []EvidenceDraft `json:"evidence,omitempty"`
}

type EvidenceDraft struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

type Tool interface {
	Name() string
	Description() string
	Schema() json.RawMessage

	Execute(
		ctx context.Context,
		args json.RawMessage,
	) (Result, error)
}
