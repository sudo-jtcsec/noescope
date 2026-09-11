package surface

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

const checkpointSchemaVersion = "1"

type RunOptions struct {
	RunRoot          string
	RepositoryRoot   string
	RepositoryCommit string
	Resume           bool
	Manifest         *runpkg.Run
}

type shardCheckpoint struct {
	SchemaVersion    string               `json:"schema_version"`
	RepositoryCommit string               `json:"repository_commit"`
	TaskID           string               `json:"task_id"`
	Category         Category             `json:"category"`
	Candidates       []string             `json:"candidates"`
	SubmitSchemaHash string               `json:"submit_schema_sha256"`
	Result           investigation.Result `json:"result"`
}

type checkpointStore struct {
	runRoot          string
	repositoryCommit string
	resume           bool
	manifest         *runpkg.Run
}

func newCheckpointStore(options RunOptions) *checkpointStore {
	if options.RunRoot == "" {
		return nil
	}
	return &checkpointStore{
		runRoot: options.RunRoot, repositoryCommit: options.RepositoryCommit,
		resume: options.Resume, manifest: options.Manifest,
	}
}

func (s *checkpointStore) load(
	task investigation.Task,
	category Category,
	candidates []string,
) (*investigation.Result, bool, error) {
	if s == nil || !s.resume {
		return nil, false, nil
	}
	path := s.path(task.ID, category)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read Surface checkpoint %s: %w", task.ID, err)
	}
	var checkpoint shardCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return nil, false, fmt.Errorf("decode Surface checkpoint %s: %w", task.ID, err)
	}
	expectedCandidates := append([]string(nil), candidates...)
	if checkpoint.SchemaVersion != checkpointSchemaVersion {
		return nil, false, fmt.Errorf(
			"Surface checkpoint %s has incompatible schema version %q (expected %q)",
			task.ID, checkpoint.SchemaVersion, checkpointSchemaVersion,
		)
	}
	if checkpoint.RepositoryCommit != s.repositoryCommit {
		return nil, false, fmt.Errorf(
			"Surface checkpoint %s repository commit mismatch: recorded %q, current %q",
			task.ID, checkpoint.RepositoryCommit, s.repositoryCommit,
		)
	}
	if checkpoint.TaskID != task.ID || checkpoint.Category != category ||
		!reflect.DeepEqual(checkpoint.Candidates, expectedCandidates) ||
		checkpoint.SubmitSchemaHash != submitSchemaHash(task.SubmitSchema) {
		return nil, false, fmt.Errorf(
			"Surface checkpoint %s is incompatible with the current task, candidate set, or submit schema",
			task.ID,
		)
	}
	result := checkpoint.Result
	return &result, true, nil
}

func (s *checkpointStore) save(
	task investigation.Task,
	category Category,
	candidates []string,
	result *investigation.Result,
) error {
	if s == nil {
		return nil
	}
	checkpoint := shardCheckpoint{
		SchemaVersion: checkpointSchemaVersion, RepositoryCommit: s.repositoryCommit,
		TaskID: task.ID, Category: category,
		Candidates:       append([]string(nil), candidates...),
		SubmitSchemaHash: submitSchemaHash(task.SubmitSchema),
		Result:           *result,
	}
	raw, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Surface checkpoint %s: %w", task.ID, err)
	}
	path := s.path(task.ID, category)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create Surface checkpoint directory: %w", err)
	}
	if err := writeAtomic(path, raw); err != nil {
		return fmt.Errorf("write Surface checkpoint %s: %w", task.ID, err)
	}
	return s.setState(task.ID, runpkg.SurfaceShardState{
		Status: "completed", Category: string(category),
		Candidates: append([]string(nil), candidates...),
		Checkpoint: relativeCheckpointPath(s.runRoot, path),
	})
}

func (s *checkpointStore) state(taskID string) (runpkg.SurfaceShardState, bool) {
	if s == nil || s.manifest == nil {
		return runpkg.SurfaceShardState{}, false
	}
	state, ok := s.manifest.Surface[taskID]
	return state, ok
}

func (s *checkpointStore) setState(
	taskID string,
	state runpkg.SurfaceShardState,
) error {
	if s == nil || s.manifest == nil {
		return nil
	}
	return s.manifest.SetSurfaceShard(taskID, state)
}

func (s *checkpointStore) path(taskID string, category Category) string {
	name := strings.TrimPrefix(taskID, "surface."+string(category)+".")
	if name == taskID || name == "" {
		name = "all"
	}
	name = strings.ReplaceAll(name, ".", "_") + ".json"
	return filepath.Join(s.runRoot, "work", "surface", string(category), name)
}

func submitSchemaHash(schema json.RawMessage) string {
	sum := sha256.Sum256(schema)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func relativeCheckpointPath(runRoot, path string) string {
	relative, err := filepath.Rel(runRoot, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}
