package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
)

const SchemaVersion = "1"

type StartOptions struct {
	RepositoryRoot   string
	RepositoryCommit string
	Through          string
}

type SurfaceShardState struct {
	Status     string   `json:"status"`
	Category   string   `json:"category"`
	Candidates []string `json:"candidates"`
	Checkpoint string   `json:"checkpoint,omitempty"`
	Children   []string `json:"children,omitempty"`
	Failure    string   `json:"failure,omitempty"`
}

type Run struct {
	SchemaVersion    string                       `json:"schema_version,omitempty"`
	ID               string                       `json:"id"`
	Command          string                       `json:"command"`
	StartedAt        time.Time                    `json:"started_at"`
	RepositoryRoot   string                       `json:"repository_root,omitempty"`
	RepositoryCommit string                       `json:"repository_commit,omitempty"`
	Through          string                       `json:"through,omitempty"`
	CompletedStages  []string                     `json:"completed_stages,omitempty"`
	Surface          map[string]SurfaceShardState `json:"surface,omitempty"`
	FeatureAttempt   int                          `json:"feature_attempt,omitempty"`
	Root             string                       `json:"-"`
}

func Start(projectRoot, command string) (*Run, error) {
	return StartWithOptions(projectRoot, command, StartOptions{})
}

func StartWithOptions(
	projectRoot string,
	command string,
	options StartOptions,
) (*Run, error) {
	r := &Run{
		SchemaVersion:    SchemaVersion,
		ID:               id.New("run"),
		Command:          command,
		StartedAt:        time.Now().UTC(),
		RepositoryRoot:   options.RepositoryRoot,
		RepositoryCommit: options.RepositoryCommit,
		Through:          options.Through,
		CompletedStages:  []string{},
		Surface:          map[string]SurfaceShardState{},
	}

	r.Root = filepath.Join(
		projectRoot,
		".noescope",
		"runs",
		r.ID,
	)

	if err := os.MkdirAll(
		filepath.Join(r.Root, "output"),
		0755,
	); err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}

	if err := Save(r); err != nil {
		return nil, err
	}

	return r, nil
}

func Open(projectRoot, runID string) (*Run, error) {
	if runID == "" || filepath.Base(runID) != runID ||
		strings.ContainsAny(runID, `/\\`) {
		return nil, fmt.Errorf("invalid run ID %q", runID)
	}
	root := filepath.Join(projectRoot, ".noescope", "runs", runID)
	raw, err := os.ReadFile(filepath.Join(root, "run.json"))
	if err != nil {
		return nil, fmt.Errorf("open run %q: %w", runID, err)
	}
	var value Run
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode run %q: %w", runID, err)
	}
	value.Root = root
	if value.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf(
			"run %q has incompatible manifest schema %q (expected %q)",
			runID,
			value.SchemaVersion,
			SchemaVersion,
		)
	}
	if value.Surface == nil {
		value.Surface = map[string]SurfaceShardState{}
	}
	return &value, nil
}

func Save(value *Run) error {
	if value == nil || value.Root == "" {
		return fmt.Errorf("run root is required")
	}
	value.CompletedStages = uniqueSorted(value.CompletedStages)
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run manifest: %w", err)
	}
	temporary, err := os.CreateTemp(value.Root, ".run-*.json")
	if err != nil {
		return fmt.Errorf("create run manifest temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write run manifest temporary file: %w", err)
	}
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return fmt.Errorf("set run manifest permissions: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close run manifest temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(value.Root, "run.json")); err != nil {
		return fmt.Errorf("publish run manifest: %w", err)
	}
	return nil
}

func (r *Run) ValidateRepository(root, commit string) error {
	if r.RepositoryRoot != root {
		return fmt.Errorf(
			"run %q repository root mismatch: recorded %q, current %q",
			r.ID,
			r.RepositoryRoot,
			root,
		)
	}
	if r.RepositoryCommit != commit {
		return fmt.Errorf(
			"run %q repository commit mismatch: recorded %q, current %q",
			r.ID,
			r.RepositoryCommit,
			commit,
		)
	}
	return nil
}

func (r *Run) StageCompleted(stage string) bool {
	for _, completed := range r.CompletedStages {
		if completed == stage {
			return true
		}
	}
	return false
}

func (r *Run) MarkStageCompleted(stage string) error {
	if !r.StageCompleted(stage) {
		r.CompletedStages = append(r.CompletedStages, stage)
	}
	return Save(r)
}

func (r *Run) SetThrough(stage string) error {
	r.Through = stage
	return Save(r)
}

func (r *Run) BeginFeatureRerun() error {
	r.FeatureAttempt++
	completed := r.CompletedStages[:0]
	for _, stage := range r.CompletedStages {
		if stage != "features" {
			completed = append(completed, stage)
		}
	}
	r.CompletedStages = completed
	r.Through = "features"
	return Save(r)
}

func (r *Run) BeginSurfaceRerun() error {
	r.FeatureAttempt++
	completed := r.CompletedStages[:0]
	for _, stage := range r.CompletedStages {
		if stage != "surface" && stage != "features" {
			completed = append(completed, stage)
		}
	}
	r.CompletedStages = completed
	return Save(r)
}

func (r *Run) SetSurfaceShard(taskID string, state SurfaceShardState) error {
	if r.Surface == nil {
		r.Surface = map[string]SurfaceShardState{}
	}
	state.Candidates = append([]string(nil), state.Candidates...)
	state.Children = append([]string(nil), state.Children...)
	sort.Strings(state.Candidates)
	sort.Strings(state.Children)
	r.Surface[taskID] = state
	return Save(r)
}

func uniqueSorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) < 2 {
		return result
	}
	write := 1
	for _, value := range result[1:] {
		if value != result[write-1] {
			result[write] = value
			write++
		}
	}
	return result[:write]
}
