package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type ReadFileTool struct {
	repo *repository.Repository
}

type readFileArgs struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func NewReadFileTool(repo *repository.Repository) *ReadFileTool {
	return &ReadFileTool{repo: repo}
}

func (t *ReadFileTool) Name() string {
	return "read_file"
}

func (t *ReadFileTool) Description() string {
	return "Read a range of lines from a text file inside the repository."
}

func (t *ReadFileTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": {
				"type": "string"
			},
			"start_line": {
				"type": "integer",
				"minimum": 1
			},
			"end_line": {
				"type": "integer",
				"minimum": 1
			}
		},
		"required": ["path"],
		"additionalProperties": false
	}`)
}

func (t *ReadFileTool) Execute(
	ctx context.Context,
	raw json.RawMessage,
) (tools.Result, error) {
	var args readFileArgs

	if err := json.Unmarshal(raw, &args); err != nil {
		return tools.Result{}, fmt.Errorf("parse read_file args: %w", err)
	}

	result, err := t.repo.ReadFile(
		args.Path,
		args.StartLine,
		args.EndLine,
	)
	if err != nil {
		return tools.Result{}, err
	}

	data, err := json.Marshal(result)
	if err != nil {
		return tools.Result{}, err
	}

	evidence := tools.EvidenceDraft{
		Kind:      "source",
		Path:      result.Path,
		StartLine: result.StartLine,
		EndLine:   result.EndLine,
		Summary:   "Source file content read by investigation.",
	}

	return tools.Result{
		Content:  data,
		Evidence: []tools.EvidenceDraft{evidence},
	}, nil
}
