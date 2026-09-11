package runtimeverify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
)

var runtimeEvidenceKinds = map[string]struct{}{
	"browser_navigation": {}, "dom_observation": {},
	"accessibility_observation": {}, "network_request": {},
	"network_response": {}, "console_message": {}, "screenshot": {},
	"runtime_assertion": {},
}

type EvidenceRecord struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	InterfaceID string            `json:"interface_id,omitempty"`
	Summary     string            `json:"summary"`
	URL         string            `json:"url,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

type EvidenceStore struct {
	path     string
	redactor *Redactor
	mu       sync.Mutex
	ids      map[string]struct{}
}

func NewEvidenceStore(runtimeRoot string, redactor *Redactor) *EvidenceStore {
	return &EvidenceStore{
		path: filepath.Join(runtimeRoot, "evidence.jsonl"), redactor: redactor,
		ids: map[string]struct{}{},
	}
}

func (s *EvidenceStore) Add(record EvidenceRecord) (EvidenceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := runtimeEvidenceKinds[record.Kind]; !ok {
		return EvidenceRecord{}, fmt.Errorf("unsupported runtime evidence kind %q", record.Kind)
	}
	record.ID = id.New("rev")
	record.CreatedAt = time.Now().UTC()
	record.Summary = s.redactor.String(record.Summary)
	record.URL = s.redactor.URL(record.URL)
	for key, value := range record.Attributes {
		if sensitiveName(key) {
			record.Attributes[key] = redacted
		} else if strings.Contains(strings.ToLower(key), "url") ||
			strings.Contains(strings.ToLower(key), "action") ||
			strings.Contains(strings.ToLower(key), "location") {
			record.Attributes[key] = s.redactor.URL(value)
		} else {
			record.Attributes[key] = s.redactor.String(value)
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return EvidenceRecord{}, err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return EvidenceRecord{}, fmt.Errorf("open runtime evidence: %w", err)
	}
	encodeErr := json.NewEncoder(file).Encode(record)
	closeErr := file.Close()
	if encodeErr != nil {
		return EvidenceRecord{}, fmt.Errorf("write runtime evidence: %w", encodeErr)
	}
	if closeErr != nil {
		return EvidenceRecord{}, fmt.Errorf("close runtime evidence: %w", closeErr)
	}
	s.ids[record.ID] = struct{}{}
	return record, nil
}

func (s *EvidenceStore) Exists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}
