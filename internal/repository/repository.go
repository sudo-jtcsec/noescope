package repository

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Repository struct {
	Root string
}

func Open(path string) (*Repository, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve repository path: %w", err)
	}

	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository symlinks: %w", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat repository: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("repository root is not a directory: %s", root)
	}

	return &Repository{Root: root}, nil
}

// Resolve validates an existing path and guarantees it remains inside
// the configured repository root, including after symlink resolution.
func (r *Repository) Resolve(path string) (string, error) {
	if path == "" {
		path = "."
	}

	if filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}

	candidate := filepath.Join(r.Root, path)

	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}

	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}

	rel, err := filepath.Rel(r.Root, resolved)
	if err != nil {
		return "", fmt.Errorf("calculate relative path: %w", err)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root")
	}

	return resolved, nil
}
