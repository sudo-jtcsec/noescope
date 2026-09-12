package coretests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
)

type EvidenceRecord struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	TestID      string            `json:"test_id"`
	InterfaceID string            `json:"interface_id,omitempty"`
	Summary     string            `json:"summary"`
	URL         string            `json:"url,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

type EvidenceStore struct {
	path     string
	redactor *runtimeverify.Redactor
	mu       sync.Mutex
}

func NewEvidenceStore(root string, redactor *runtimeverify.Redactor) *EvidenceStore {
	return &EvidenceStore{path: filepath.Join(root, "evidence.jsonl"), redactor: redactor}
}

func (s *EvidenceStore) Add(record EvidenceRecord) (EvidenceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.Kind != "test_step" && record.Kind != "test_assertion" &&
		record.Kind != "test_cleanup" && record.Kind != "test_execution" {
		return EvidenceRecord{}, fmt.Errorf("unsupported test evidence kind %q", record.Kind)
	}
	record.ID = id.New("tev")
	record.CreatedAt = time.Now().UTC()
	record.Summary = s.redactor.String(record.Summary)
	record.URL = s.redactor.URL(record.URL)
	for key, value := range record.Attributes {
		if sensitiveEvidenceAttribute(key) {
			record.Attributes[key] = "[REDACTED]"
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
		return EvidenceRecord{}, err
	}
	encodeErr := json.NewEncoder(file).Encode(record)
	closeErr := file.Close()
	if encodeErr != nil {
		return EvidenceRecord{}, encodeErr
	}
	if closeErr != nil {
		return EvidenceRecord{}, closeErr
	}
	return record, nil
}

func sensitiveEvidenceAttribute(key string) bool {
	key = strings.ToLower(key)
	for _, term := range []string{"password", "token", "secret", "authorization", "cookie", "api_key", "apikey", "otp", "totp", "one_time", "one-time"} {
		if strings.Contains(key, term) {
			return true
		}
	}
	return false
}
