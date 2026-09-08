package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type ListFilesTool struct {
	repo *repository.Repository
}

type listFilesArgs struct {
	Path  string `json:"path"`
	Depth int    `json:"depth"`
}

func NewListFilesTool(repo *repository.Repository) *ListFilesTool {
	return &ListFilesTool{repo: repo}
}

func (t *ListFilesTool) Name() string {
	return "list_files"
}

func (t *ListFilesTool) Description() string {
	return "List files and directories beneath a repository path to a limited depth."
}

func (t *ListFilesTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": {
				"type": "string",
				"description": "Repository-relative path to inspect."
			},
			"depth": {
				"type": "integer",
				"minimum": 0,
				"maximum": 10
			}
		},
		"additionalProperties": false
	}`)
}

func (t *ListFilesTool) Execute(
	ctx context.Context,
	raw json.RawMessage,
) (tools.Result, error) {
	args := listFilesArgs{
		Path:  ".",
		Depth: 2,
	}

	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return tools.Result{}, fmt.Errorf("parse list_files args: %w", err)
		}
	}

	entries, err := t.repo.ListFiles(args.Path, args.Depth)
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
