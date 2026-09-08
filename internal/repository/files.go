package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FileEntry struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size,omitempty"`
}

type FileInfo struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Lines     int    `json:"lines"`
	Extension string `json:"extension"`
	Language  string `json:"language,omitempty"`
	Binary    bool   `json:"binary"`
	SHA256    string `json:"sha256"`
}

func (r *Repository) ListFiles(path string, depth int) ([]FileEntry, error) {
	if depth < 0 {
		depth = 0
	}

	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}

	baseRel, err := filepath.Rel(r.Root, resolved)
	if err != nil {
		return nil, err
	}

	var entries []FileEntry

	err = filepath.WalkDir(resolved, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		relToBase, err := filepath.Rel(resolved, current)
		if err != nil {
			return nil
		}

		if relToBase == "." {
			return nil
		}

		currentDepth := len(strings.Split(filepath.Clean(relToBase), string(filepath.Separator)))

		if entry.IsDir() && currentDepth > depth {
			return filepath.SkipDir
		}

		if currentDepth > depth {
			return nil
		}

		relToRepo, err := filepath.Rel(r.Root, current)
		if err != nil {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}

		entries = append(entries, FileEntry{
			Path:  filepath.ToSlash(relToRepo),
			Name:  entry.Name(),
			IsDir: entry.IsDir(),
			Size:  info.Size(),
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list files: %w", err)
	}

	_ = baseRel

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	return entries, nil
}

func (r *Repository) FindFiles(pattern, path string) ([]FileEntry, error) {
	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}

	var matches []FileEntry

	err = filepath.WalkDir(resolved, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}

		if entry.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(r.Root, current)
		if err != nil {
			return nil
		}

		relSlash := filepath.ToSlash(rel)

		matchedName, _ := filepath.Match(pattern, entry.Name())
		matchedPath, _ := filepath.Match(pattern, relSlash)

		if !matchedName && !matchedPath {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}

		matches = append(matches, FileEntry{
			Path:  relSlash,
			Name:  entry.Name(),
			IsDir: false,
			Size:  info.Size(),
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find files: %w", err)
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Path < matches[j].Path
	})

	return matches, nil
}

func (r *Repository) FileInfo(path string) (*FileInfo, error) {
	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}

	if stat.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", path)
	}

	binary, err := isBinaryFile(resolved)
	if err != nil {
		return nil, err
	}

	lines := 0
	if !binary {
		lines, err = lineCount(resolved)
		if err != nil {
			return nil, err
		}
	}

	hash, err := hashFile(resolved)
	if err != nil {
		return nil, err
	}

	rel, err := filepath.Rel(r.Root, resolved)
	if err != nil {
		return nil, err
	}

	ext := filepath.Ext(resolved)

	return &FileInfo{
		Path:      filepath.ToSlash(rel),
		Name:      filepath.Base(resolved),
		Size:      stat.Size(),
		Lines:     lines,
		Extension: ext,
		Language:  languageFromExtension(ext),
		Binary:    binary,
		SHA256:    hash,
	}, nil
}

func isBinaryFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 8192)

	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}

	for _, b := range buf[:n] {
		if b == 0 {
			return true, nil
		}
	}

	return false, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
