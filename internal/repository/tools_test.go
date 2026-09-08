package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func createTestRepo(t *testing.T) *Repository {
	t.Helper()

	root := t.TempDir()

	files := map[string]string{
		"src/auth.php": `<?php
function requireLogin() {}
function hasPermission($permission) {}
`,
		"src/customer.php": `<?php
requireLogin();
if (hasPermission("customer.edit")) {
    echo "allowed";
}
`,
		"README.md": "# Test App\n",
	}

	for path, content := range files {
		full := filepath.Join(root, path)

		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	repo, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	return repo
}

func TestListFiles(t *testing.T) {
	repo := createTestRepo(t)

	entries, err := repo.ListFiles(".", 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) == 0 {
		t.Fatal("expected file entries")
	}
}

func TestFindFiles(t *testing.T) {
	repo := createTestRepo(t)

	entries, err := repo.FindFiles("*.php", ".")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 PHP files, got %d", len(entries))
	}
}

func TestReadFile(t *testing.T) {
	repo := createTestRepo(t)

	result, err := repo.ReadFile("src/auth.php", 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(result.Lines))
	}
}

func TestLiteralSearch(t *testing.T) {
	repo := createTestRepo(t)

	result, err := repo.Search(SearchOptions{
		Query:        "hasPermission",
		Path:         ".",
		MaxResults:   20,
		ContextLines: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Matches) < 2 {
		t.Fatalf("expected at least 2 matches, got %d", len(result.Matches))
	}
}

func TestRegexSearch(t *testing.T) {
	repo := createTestRepo(t)

	result, err := repo.Search(SearchOptions{
		Query:         `customer\.(edit|view)`,
		Path:          ".",
		Regex:         true,
		CaseSensitive: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 regex match, got %d", len(result.Matches))
	}
}

func TestFileInfo(t *testing.T) {
	repo := createTestRepo(t)

	info, err := repo.FileInfo("src/auth.php")
	if err != nil {
		t.Fatal(err)
	}

	if info.Language != "PHP" {
		t.Fatalf("expected PHP, got %q", info.Language)
	}

	if info.SHA256 == "" {
		t.Fatal("expected SHA256")
	}
}
