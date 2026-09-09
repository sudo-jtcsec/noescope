package repositorytools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type SearchTool struct {
	repo *repository.Repository
}

type searchArgs struct {
	Query         string `json:"query"`
	Path          string `json:"path"`
	Regex         bool   `json:"regex"`
	CaseSensitive bool   `json:"case_sensitive"`
	FileGlob      string `json:"file_glob"`
	MaxResults    int    `json:"max_results"`
	ContextLines  int    `json:"context_lines"`
}

func NewSearchTool(repo *repository.Repository) *SearchTool {
	return &SearchTool{repo: repo}
}

func (t *SearchTool) Name() string {
	return "search"
}

func (t *SearchTool) Description() string {
	return "Search text files in the repository using literal text or regular expressions."
}

func (t *SearchTool) Schema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": {"type": "string"},
			"path": {"type": "string"},
			"regex": {"type": "boolean"},
			"case_sensitive": {"type": "boolean"},
			"file_glob": {"type": "string"},
			"max_results": {
				"type": "integer",
				"minimum": 1,
				"maximum": 500
			},
			"context_lines": {
				"type": "integer",
				"minimum": 0,
				"maximum": 20
			}
		},
		"required": ["query"],
		"additionalProperties": false
	}`)
}

func (t *SearchTool) Execute(
	ctx context.Context,
	raw json.RawMessage,
) (tools.Result, error) {
	args := searchArgs{
		Path:         ".",
		MaxResults:   50,
		ContextLines: 2,
	}

	if err := json.Unmarshal(raw, &args); err != nil {
		return tools.Result{}, fmt.Errorf("parse search args: %w", err)
	}

	result, err := t.repo.Search(repository.SearchOptions{
		Query:         args.Query,
		Path:          args.Path,
		Regex:         args.Regex,
		CaseSensitive: args.CaseSensitive,
		FileGlob:      args.FileGlob,
		MaxResults:    args.MaxResults,
		ContextLines:  args.ContextLines,
	})
	if err != nil {
		return tools.Result{}, err
	}

	data, err := json.Marshal(result)
	if err != nil {
		return tools.Result{}, err
	}

	evidence := make([]tools.EvidenceDraft, 0, len(result.Matches))

	for _, match := range result.Matches {
		evidence = append(evidence, tools.EvidenceDraft{
			Kind:      "source",
			Path:      match.Path,
			StartLine: match.StartLine,
			EndLine:   match.EndLine,
			Summary:   fmt.Sprintf("Search match for %q.", args.Query),
		})
	}

	return tools.Result{
		Content:  data,
		Evidence: evidence,
	}, nil
}
