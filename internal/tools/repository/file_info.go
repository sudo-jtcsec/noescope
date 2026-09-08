package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type FileInfoTool struct {
	repo *repository.Repository
}

type fileInfoArgs struct {
	Path string `json:"path"`
}

func NewFileInfoTool(repo *repository.Repository) *FileInfoTool {
	return &FileInfoTool{repo: repo}
}

func (t *FileInfoTool) Name() string {
	return "file_info"
}

func (t *FileInfoTool) Description() string {
	return "Return metadata about a repository file including size, line count, type, language, binary status, and SHA256."
}

func (t *FileInfoTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": {
				"type": "string"
			}
		},
		"required": ["path"],
		"additionalProperties": false
	}`)
}

func (t *FileInfoTool) Execute(
	ctx context.Context,
	raw json.RawMessage,
) (tools.Result, error) {
	var args fileInfoArgs

	if err := json.Unmarshal(raw, &args); err != nil {
		return tools.Result{}, fmt.Errorf("parse file_info args: %w", err)
	}

	info, err := t.repo.FileInfo(args.Path)
	if err != nil {
		return tools.Result{}, err
	}

	data, err := json.Marshal(info)
	if err != nil {
		return tools.Result{}, err
	}

	return tools.Result{
		Content: data,
	}, nil
}
