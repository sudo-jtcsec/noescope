package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
)

type Run struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	StartedAt time.Time `json:"started_at"`
	Root      string    `json:"-"`
}

func Start(projectRoot, command string) (*Run, error) {
	r := &Run{
		ID:        id.New("run"),
		Command:   command,
		StartedAt: time.Now().UTC(),
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

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(
		filepath.Join(r.Root, "run.json"),
		data,
		0644,
	); err != nil {
		return nil, err
	}

	return r, nil
}
