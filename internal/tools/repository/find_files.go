package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type FindFilesTool struct {
	repo *repository.Repository
}

type findFilesArgs struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
}

func NewFindFilesTool(repo *repository.Repository) *FindFilesTool {
	return &FindFilesTool{repo: repo}
}

func (t *FindFilesTool) Name() string {
	return "find_files"
}

func (t *FindFilesTool) Description() string {
	return "Find repository files matching a filename or path glob."
}

func (t *FindFilesTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"pattern": {
				"type": "string"
			},
			"path": {
				"type": "string"
			}
		},
		"required": ["pattern"],
		"additionalProperties": false
	}`)
}

func (t *FindFilesTool) Execute(
	ctx context.Context,
	raw json.RawMessage,
) (tools.Result, error) {
	args := findFilesArgs{
		Path: ".",
	}

	if err := json.Unmarshal(raw, &args); err != nil {
		return tools.Result{}, fmt.Errorf("parse find_files args: %w", err)
	}

	if args.Pattern == "" {
		return tools.Result{}, fmt.Errorf("pattern is required")
	}

	entries, err := t.repo.FindFiles(args.Pattern, args.Path)
	if err != nil {
		return tools.Result{}, err
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return tools.Result{}, err
	}

	return tools.Result{
		Content: data,
	}, nil
}
