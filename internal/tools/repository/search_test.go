package repositorytools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/repository"
)

func TestSearchWithoutMatchesProducesEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "main.go"),
		[]byte("package main\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	repo, err := repository.Open(root)
	if err != nil {
		t.Fatal(err)
	}

	result, err := NewSearchTool(repo).Execute(
		context.Background(),
		json.RawMessage(`{"query":"hasPermission"}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Evidence) != 1 {
		t.Fatalf(
			"expected one no-match evidence record, got %d",
			len(result.Evidence),
		)
	}

	record := result.Evidence[0]
	if record.Kind != "search" || record.Path != "." {
		t.Fatalf("unexpected evidence record: %#v", record)
	}
	if !strings.Contains(record.Summary, "returned no matches") {
		t.Fatalf("unexpected evidence summary: %q", record.Summary)
	}
}
