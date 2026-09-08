package repositorytools

import (
	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

func RegisterAll(
	registry *tools.Registry,
	repo *repository.Repository,
) error {
	all := []tools.Tool{
		NewRepoInfoTool(repo),
		NewListFilesTool(repo),
		NewFindFilesTool(repo),
		NewFileInfoTool(repo),
		NewReadFileTool(repo),
		NewSearchTool(repo),
	}

	for _, tool := range all {
		if err := registry.Register(tool); err != nil {
			return err
		}
	}

	return nil
}
