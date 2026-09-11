package features

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
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

const checkpointSchemaVersion = "1"

type featureCheckpoint struct {
	SchemaVersion    string               `json:"schema_version"`
	RepositoryCommit string               `json:"repository_commit"`
	FeatureAttempt   int                  `json:"feature_attempt"`
	TaskID           string               `json:"task_id"`
	ModuleID         string               `json:"module_id"`
	InputInterfaces  []string             `json:"input_interfaces"`
	SubmitSchemaHash string               `json:"submit_schema_sha256"`
	PriorHash        string               `json:"prior_sha256"`
	Result           investigation.Result `json:"result"`
}

type checkpointStore struct {
	options   RunOptions
	priorHash string
}

func newCheckpointStore(options RunOptions, priorHash string) *checkpointStore {
	if options.RunRoot == "" {
		return nil
	}
	return &checkpointStore{options: options, priorHash: priorHash}
}

func (s *checkpointStore) load(
	task investigation.Task,
	moduleID string,
	inputInterfaces []string,
) (*investigation.Result, bool, error) {
	if s == nil || !s.options.Resume {
		return nil, false, nil
	}
	raw, err := os.ReadFile(s.path(moduleID))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read Feature checkpoint %q: %w", moduleID, err)
	}
	var checkpoint featureCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return nil, false, fmt.Errorf("decode Feature checkpoint %q: %w", moduleID, err)
	}
	if checkpoint.FeatureAttempt != s.options.FeatureAttempt {
		return nil, false, nil
	}
	if checkpoint.SchemaVersion != checkpointSchemaVersion {
		return nil, false, fmt.Errorf(
			"Feature checkpoint %q has incompatible schema version %q",
			moduleID, checkpoint.SchemaVersion,
		)
	}
	if checkpoint.RepositoryCommit != s.options.RepositoryCommit {
		return nil, false, fmt.Errorf("Feature checkpoint %q repository commit mismatch", moduleID)
	}
	expectedInterfaces := sortedUnique(inputInterfaces)
	if checkpoint.TaskID != task.ID || checkpoint.ModuleID != moduleID ||
		!reflect.DeepEqual(checkpoint.InputInterfaces, expectedInterfaces) ||
		checkpoint.SubmitSchemaHash != schemaHash(task.SubmitSchema) ||
		checkpoint.PriorHash != s.priorHash {
		return nil, false, fmt.Errorf(
			"Feature checkpoint %q is incompatible with its task, inputs, schema, or canonical prior stages",
			moduleID,
		)
	}
	result := checkpoint.Result
	return &result, true, nil
}

func (s *checkpointStore) save(
	task investigation.Task,
	moduleID string,
	inputInterfaces []string,
	result *investigation.Result,
) error {
	if s == nil {
		return nil
	}
	checkpoint := featureCheckpoint{
		SchemaVersion: checkpointSchemaVersion, RepositoryCommit: s.options.RepositoryCommit,
		FeatureAttempt: s.options.FeatureAttempt, TaskID: task.ID, ModuleID: moduleID,
		InputInterfaces:  sortedUnique(inputInterfaces),
		SubmitSchemaHash: schemaHash(task.SubmitSchema), PriorHash: s.priorHash,
		Result: *result,
	}
	raw, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Feature checkpoint %q: %w", moduleID, err)
	}
	path := s.path(moduleID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create Feature checkpoint directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".feature-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(raw); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish Feature checkpoint %q: %w", moduleID, err)
	}
	return nil
}

func (s *checkpointStore) path(moduleID string) string {
	name := strings.ReplaceAll(moduleID, ".", "_") + ".json"
	return filepath.Join(s.options.RunRoot, "work", "features", name)
}

func schemaHash(schema json.RawMessage) string {
	sum := sha256.Sum256(schema)
	return hex.EncodeToString(sum[:])
}

func featurePriorHash(
	taskContext json.RawMessage,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) (string, error) {
	value := struct {
		Context        json.RawMessage          `json:"context"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
		Entities       *entities.Findings       `json:"entities"`
		Surface        *surface.Findings        `json:"surface"`
	}{taskContext, authenticationFindings, authorizationFindings, entityFindings, surfaceFindings}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("hash canonical Feature inputs: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
