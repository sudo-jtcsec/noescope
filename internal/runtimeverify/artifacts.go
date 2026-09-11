package runtimeverify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

type Session struct {
	Root    string
	Runtime *Runtime
}

func NewSession(sourceRunRoot string, application *model.Application, baseURL string) (*Session, error) {
	redactor := NewRedactor()
	baseURL = redactor.URL(baseURL)
	if _, err := ResolveRoute(baseURL, "/", nil); err != nil {
		return nil, err
	}
	runtimeID := id.New("runtime")
	root := filepath.Join(sourceRunRoot, "runtime", runtimeID)
	if err := os.MkdirAll(filepath.Join(root, "screenshots"), 0755); err != nil {
		return nil, fmt.Errorf("create runtime run: %w", err)
	}
	return &Session{Root: root, Runtime: &Runtime{
		SchemaVersion: SchemaVersion, RuntimeID: runtimeID,
		SourceRunID:              application.Metadata.RunID,
		SourceGitCommit:          application.Metadata.Source.GitCommit,
		ApplicationSchemaVersion: application.SchemaVersion,
		BaseURL:                  baseURL, StartedAt: time.Now().UTC(),
		Status:         RunStatusRunning,
		Application:    ApplicationObservation{Status: StatusUnknown, EvidenceIDs: []string{}},
		Authentication: AuthenticationObservation{Status: StatusNotAttempted, EvidenceIDs: []string{}},
		Interfaces:     []InterfaceObservation{}, Features: []FeatureObservation{},
		ConsoleErrors: []ConsoleObservation{}, ObservationErrors: []ObservationError{},
	}}, nil
}

func (s *Session) Write() (string, string, error) {
	if s.Runtime.Status == RunStatusRunning {
		MarkFailure(s.Runtime, "runtime", "completion", "runtime session ended before verification completed", nil)
	}
	s.Runtime.CompletedAt = time.Now().UTC()
	normalizeRuntime(s.Runtime)
	jsonData, err := json.MarshalIndent(s.Runtime, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal runtime artifact: %w", err)
	}
	markdownData := Markdown(s.Runtime)
	jsonPath := filepath.Join(s.Root, "runtime.json")
	markdownPath := filepath.Join(s.Root, "runtime.md")
	if err := atomicWrite(jsonPath, jsonData, 0600); err != nil {
		return "", "", err
	}
	if err := atomicWrite(markdownPath, markdownData, 0600); err != nil {
		return "", "", err
	}
	return jsonPath, markdownPath, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runtime-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish runtime artifact: %w", err)
	}
	return nil
}
