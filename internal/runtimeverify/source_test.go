package runtimeverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/model"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

func TestLoadSourceModelSelectsLatestCompatibleCompleteRun(t *testing.T) {
	projectRoot := t.TempDir()
	older := writeSourceRun(t, projectRoot, "commit-one", true)
	older.StartedAt = older.StartedAt.Add(-time.Hour)
	if err := runpkg.Save(older); err != nil {
		t.Fatal(err)
	}
	newerIncomplete := writeSourceRun(t, projectRoot, "commit-one", false)
	newerIncomplete.StartedAt = time.Now().UTC().Add(time.Hour)
	if err := runpkg.Save(newerIncomplete); err != nil {
		t.Fatal(err)
	}

	source, err := LoadSourceModel(projectRoot, "", "/repo", "commit-one")
	if err != nil {
		t.Fatal(err)
	}
	if source.Run.ID != older.ID || source.Application.Metadata.RunID != older.ID {
		t.Fatalf("selected wrong source run: %#v", source.Run)
	}
	if _, err := LoadSourceModel(projectRoot, newerIncomplete.ID, "/repo", "commit-one"); err == nil ||
		!strings.Contains(err.Error(), "complete source application") {
		t.Fatalf("explicit incomplete run was not rejected: %v", err)
	}
	if _, err := LoadSourceModel(projectRoot, older.ID, "/repo", "different"); err == nil ||
		!strings.Contains(err.Error(), "commit mismatch") {
		t.Fatalf("commit mismatch was not rejected: %v", err)
	}
}

func TestLoadSourceModelRejectsIncompatibleApplicationSchema(t *testing.T) {
	projectRoot := t.TempDir()
	run := writeSourceRun(t, projectRoot, "commit-one", true)
	path := filepath.Join(run.Root, "output", "application.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"schema_version": "0.1"`, `"schema_version": "obsolete"`, 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSourceModel(projectRoot, run.ID, "/repo", "commit-one"); err == nil ||
		!strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("schema mismatch was not rejected: %v", err)
	}
}

func writeSourceRun(t *testing.T, projectRoot, commit string, complete bool) *runpkg.Run {
	t.Helper()
	run, err := runpkg.StartWithOptions(projectRoot, "discover", runpkg.StartOptions{
		RepositoryRoot: "/repo", RepositoryCommit: commit, Through: "features",
	})
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		for _, stage := range []string{
			"architecture", "authentication", "authorization", "entities", "surface", "features",
		} {
			if err := run.MarkStageCompleted(stage); err != nil {
				t.Fatal(err)
			}
		}
	}
	application := runtimeApplicationFixture()
	application.Metadata.RunID = run.ID
	application.Metadata.Source.Root = "/repo"
	application.Metadata.Source.GitCommit = commit
	application.SchemaVersion = model.SchemaVersion
	application.Discovery.Stages.Architecture.Status = "completed"
	application.Discovery.Stages.Authentication.Status = "completed"
	application.Discovery.Stages.Authorization.Status = "completed"
	application.Discovery.Stages.Entities.Status = "completed"
	application.Discovery.Stages.Surface.Status = "completed"
	application.Discovery.Stages.Features.Status = "completed"
	raw, err := json.MarshalIndent(application, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run.Root, "output", "application.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestCompleteApplicationAllowsValidatedPartialStage(t *testing.T) {
	application := runtimeApplicationFixture()
	application.Discovery.Stages.Architecture.Status = "completed"
	application.Discovery.Stages.Authentication.Status = "completed"
	application.Discovery.Stages.Authorization.Status = "completed"
	application.Discovery.Stages.Entities.Status = "completed"
	application.Discovery.Stages.Surface.Status = "partial"
	application.Discovery.Stages.Features.Status = "completed"
	if !completeApplication(application) {
		t.Fatal("validated partial stage made canonical source model unusable")
	}
	application.Discovery.Stages.Surface.Status = "blocked"
	if completeApplication(application) {
		t.Fatal("blocked stage was accepted as a complete source model")
	}
}
