package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type Record struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"task_id"`
	Kind      string    `json:"kind"`
	Path      string    `json:"path,omitempty"`
	StartLine int       `json:"start_line,omitempty"`
	EndLine   int       `json:"end_line,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	path string

	mu      sync.RWMutex
	records map[string]Record
}

func NewStore(runRoot string) *Store {
	return &Store{
		path: filepath.Join(
			runRoot,
			"evidence.jsonl",
		),
		records: make(map[string]Record),
	}
}

func OpenStore(runRoot string) (*Store, error) {
	store := NewStore(runRoot)
	raw, err := os.ReadFile(store.path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read evidence store: %w", err)
	}
	lines := bytes.Split(raw, []byte{'\n'})
	for lineNumber, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf(
				"decode evidence store line %d: %w",
				lineNumber+1,
				err,
			)
		}
		if record.ID == "" {
			return nil, fmt.Errorf("evidence store line %d has no ID", lineNumber+1)
		}
		store.records[record.ID] = record
	}
	return store, nil
}

func (s *Store) AddDrafts(
	taskID string,
	drafts []tools.EvidenceDraft,
) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(drafts) == 0 {
		return nil, nil
	}

	f, err := os.OpenFile(
		s.path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open evidence store: %w",
			err,
		)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)

	records := make(
		[]Record,
		0,
		len(drafts),
	)

	for _, draft := range drafts {
		record := Record{
			ID:        id.New("ev"),
			TaskID:    taskID,
			Kind:      draft.Kind,
			Path:      draft.Path,
			StartLine: draft.StartLine,
			EndLine:   draft.EndLine,
			Summary:   draft.Summary,
			CreatedAt: time.Now().UTC(),
		}

		if err := encoder.Encode(record); err != nil {
			return nil, fmt.Errorf(
				"write evidence: %w",
				err,
			)
		}

		s.records[record.ID] = record

		records = append(
			records,
			record,
		)
	}

	return records, nil
}

func (s *Store) Exists(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.records[id]
	return ok
}

func (s *Store) Get(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.records[id]
	return record, ok
}
