package run

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenValidatesManifestSchemaAndRepositoryIdentity(t *testing.T) {
	projectRoot := t.TempDir()
	created, err := StartWithOptions(projectRoot, "discover", StartOptions{
		RepositoryRoot: "/source", RepositoryCommit: "commit-one", Through: "surface",
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(projectRoot, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.ValidateRepository("/source", "commit-one"); err != nil {
		t.Fatal(err)
	}
	if err := opened.ValidateRepository("/source", "commit-two"); err == nil ||
		!strings.Contains(err.Error(), "commit mismatch") {
		t.Fatalf("expected commit mismatch, got %v", err)
	}

	path := filepath.Join(created.Root, "run.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"schema_version": "1"`, `"schema_version": "obsolete"`, 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(projectRoot, created.ID); err == nil ||
		!strings.Contains(err.Error(), "incompatible manifest schema") {
		t.Fatalf("expected manifest schema rejection, got %v", err)
	}
}

func TestRunManifestPersistsCompletedStagesAndSurfaceState(t *testing.T) {
	projectRoot := t.TempDir()
	created, err := StartWithOptions(projectRoot, "discover", StartOptions{
		RepositoryRoot: "/source", RepositoryCommit: "commit-one", Through: "surface",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := created.MarkStageCompleted("architecture"); err != nil {
		t.Fatal(err)
	}
	if err := created.SetSurfaceShard("surface.api.group_1", SurfaceShardState{
		Status: "completed", Category: "api", Candidates: []string{"b", "a"},
		Checkpoint: "work/surface/api/group_1.json",
	}); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(projectRoot, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.StageCompleted("architecture") ||
		opened.Surface["surface.api.group_1"].Status != "completed" {
		t.Fatalf("manifest state was not persisted: %#v", opened)
	}
	got := opened.Surface["surface.api.group_1"].Candidates
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("manifest candidates are not deterministic: %v", got)
	}
}

func TestSetThroughExtendsTargetWithoutChangingRunID(t *testing.T) {
	projectRoot := t.TempDir()
	created, err := StartWithOptions(projectRoot, "discover", StartOptions{
		RepositoryRoot: "/source", RepositoryCommit: "commit-one", Through: "surface",
	})
	if err != nil {
		t.Fatal(err)
	}
	runID := created.ID
	if err := created.SetThrough("features"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(projectRoot, runID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.ID != runID || reopened.Through != "features" {
		t.Fatalf("extended run identity/target = %q/%q", reopened.ID, reopened.Through)
	}
}

func TestBeginFeatureRerunPreservesRunAndPriorStageCompletion(t *testing.T) {
	projectRoot := t.TempDir()
	created, err := StartWithOptions(projectRoot, "discover", StartOptions{
		RepositoryRoot: "/source", RepositoryCommit: "commit-one", Through: "features",
	})
	if err != nil {
		t.Fatal(err)
	}
	created.CompletedStages = []string{
		"architecture", "authentication", "authorization", "entities", "surface", "features",
	}
	if err := Save(created); err != nil {
		t.Fatal(err)
	}
	outputRoot := filepath.Join(created.Root, "output")
	if err := os.MkdirAll(outputRoot, 0755); err != nil {
		t.Fatal(err)
	}
	priorStageBytes := map[string][]byte{}
	for _, stage := range []string{
		"architecture", "authentication", "authorization", "entities", "surface",
	} {
		content := []byte("canonical-" + stage)
		priorStageBytes[stage] = content
		if err := os.WriteFile(filepath.Join(outputRoot, stage+".json"), content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	runID := created.ID
	if err := created.BeginFeatureRerun(); err != nil {
		t.Fatal(err)
	}
	if created.ID != runID || created.FeatureAttempt != 1 ||
		created.StageCompleted("features") || !created.StageCompleted("surface") {
		t.Fatalf("unexpected Feature rerun state: %#v", created)
	}
	for stage, want := range priorStageBytes {
		got, err := os.ReadFile(filepath.Join(outputRoot, stage+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("Feature rerun changed canonical %s output", stage)
		}
	}
}

func TestBeginSurfaceRerunPreservesPrerequisiteArtifactsAndRunID(t *testing.T) {
	projectRoot := t.TempDir()
	created, err := StartWithOptions(projectRoot, "discover", StartOptions{
		RepositoryRoot: "/source", RepositoryCommit: "commit-one", Through: "features",
	})
	if err != nil {
		t.Fatal(err)
	}
	created.CompletedStages = []string{
		"architecture", "authentication", "authorization", "entities", "surface", "features",
	}
	if err := Save(created); err != nil {
		t.Fatal(err)
	}
	before := map[string][32]byte{}
	for _, stage := range []string{"architecture", "authentication", "authorization", "entities"} {
		path := filepath.Join(created.Root, "output", stage+".json")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		contents := []byte("canonical-" + stage)
		if err := os.WriteFile(path, contents, 0644); err != nil {
			t.Fatal(err)
		}
		before[stage] = sha256.Sum256(contents)
	}
	runID := created.ID
	if err := created.BeginSurfaceRerun(); err != nil {
		t.Fatal(err)
	}
	if created.ID != runID || created.StageCompleted("surface") || created.StageCompleted("features") {
		t.Fatalf("Surface rerun did not invalidate only dependent stages: %#v", created)
	}
	for _, stage := range []string{"architecture", "authentication", "authorization", "entities"} {
		if !created.StageCompleted(stage) {
			t.Fatalf("prerequisite stage %s was invalidated", stage)
		}
		contents, err := os.ReadFile(filepath.Join(created.Root, "output", stage+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(contents) != before[stage] {
			t.Fatalf("prerequisite artifact %s changed", stage)
		}
	}
}
