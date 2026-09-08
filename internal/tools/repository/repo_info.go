package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type RepoInfoTool struct {
	repo *repository.Repository
}

func NewRepoInfoTool(repo *repository.Repository) *RepoInfoTool {
	return &RepoInfoTool{repo: repo}
}

func (t *RepoInfoTool) Name() string {
	return "repo_info"
}

func (t *RepoInfoTool) Description() string {
	return "Return metadata about the source repository, including root, Git branch, commit, dirty state, file count, and detected languages."
}

func (t *RepoInfoTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {},
		"additionalProperties": false
	}`)
}

func (t *RepoInfoTool) Execute(
	ctx context.Context,
	args json.RawMessage,
) (tools.Result, error) {
	info, err := t.repo.Info()
	if err != nil {
		return tools.Result{}, err
	}

	data, err := json.Marshal(info)
	if err != nil {
		return tools.Result{}, fmt.Errorf("marshal repo info: %w", err)
	}

	return tools.Result{
		Content: data,
	}, nil
}
