package runtimeverify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/sudo-jtcsec/noescope/internal/model"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

type SourceModel struct {
	Run         *runpkg.Run
	Application *model.Application
	Path        string
}

func LoadSourceModel(
	projectRoot string,
	runID string,
	repositoryRoot string,
	repositoryCommit string,
) (*SourceModel, error) {
	if runID != "" {
		return loadSourceRun(projectRoot, runID, repositoryRoot, repositoryCommit)
	}
	runsRoot := filepath.Join(projectRoot, ".noescope", "runs")
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return nil, fmt.Errorf("list source discovery runs: %w", err)
	}
	type candidate struct {
		id      string
		started int64
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		run, err := runpkg.Open(projectRoot, entry.Name())
		if err != nil || run.RepositoryRoot != repositoryRoot ||
			run.RepositoryCommit != repositoryCommit || !completeSourceRun(run) {
			continue
		}
		candidates = append(candidates, candidate{entry.Name(), run.StartedAt.UnixNano()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].started == candidates[j].started {
			return candidates[i].id > candidates[j].id
		}
		return candidates[i].started > candidates[j].started
	})
	for _, candidate := range candidates {
		source, err := loadSourceRun(
			projectRoot, candidate.id, repositoryRoot, repositoryCommit,
		)
		if err == nil {
			return source, nil
		}
	}
	return nil, fmt.Errorf(
		"no compatible complete source application model exists for repository commit %s; run noescope discover --through features first",
		repositoryCommit,
	)
}

func loadSourceRun(
	projectRoot, runID, repositoryRoot, repositoryCommit string,
) (*SourceModel, error) {
	run, err := runpkg.Open(projectRoot, runID)
	if err != nil {
		return nil, err
	}
	if err := run.ValidateRepository(repositoryRoot, repositoryCommit); err != nil {
		return nil, err
	}
	if !completeSourceRun(run) {
		return nil, fmt.Errorf("run %q does not contain a complete source application model", runID)
	}
	path := filepath.Join(run.Root, "output", "application.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source application model: %w", err)
	}
	var application model.Application
	if err := json.Unmarshal(raw, &application); err != nil {
		return nil, fmt.Errorf("decode source application model: %w", err)
	}
	if application.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf(
			"source application schema %q is incompatible with %q",
			application.SchemaVersion, model.SchemaVersion,
		)
	}
	if application.Metadata.RunID != run.ID ||
		application.Metadata.Source.GitCommit != repositoryCommit ||
		application.Metadata.Source.Root != repositoryRoot {
		return nil, fmt.Errorf("source application metadata does not match run %q", run.ID)
	}
	if !completeApplication(&application) {
		return nil, fmt.Errorf("source application model for run %q has incomplete stage provenance", run.ID)
	}
	if err := ValidateSourceReferences(&application); err != nil {
		return nil, fmt.Errorf("validate source application model: %w", err)
	}
	return &SourceModel{Run: run, Application: &application, Path: path}, nil
}

func completeApplication(application *model.Application) bool {
	stages := application.Discovery.Stages
	for _, status := range []string{
		stages.Architecture.Status, stages.Authentication.Status,
		stages.Authorization.Status, stages.Entities.Status,
		stages.Surface.Status, stages.Features.Status,
	} {
		if status != "completed" && status != "partial" {
			return false
		}
	}
	return true
}

func completeSourceRun(run *runpkg.Run) bool {
	for _, stage := range []string{
		"architecture", "authentication", "authorization", "entities", "surface", "features",
	} {
		if !run.StageCompleted(stage) {
			return false
		}
	}
	return true
}
