package repository

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Info struct {
	Root      string         `json:"root"`
	Branch    string         `json:"branch"`
	Commit    string         `json:"commit"`
	Dirty     bool           `json:"dirty"`
	FileCount int            `json:"file_count"`
	Languages map[string]int `json:"languages"`
}

func (r *Repository) Info() (*Info, error) {
	info := &Info{
		Root:      r.Root,
		Languages: make(map[string]int),
	}

	info.Branch = r.gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	info.Commit = r.gitOutput("rev-parse", "HEAD")

	status := r.gitOutput("status", "--porcelain")
	info.Dirty = status != ""

	err := filepath.WalkDir(r.Root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		info.FileCount++

		language := languageFromExtension(filepath.Ext(path))
		if language != "" {
			info.Languages[language]++
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repository: %w", err)
	}

	return info, nil
}

func (r *Repository) gitOutput(args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Root

	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func languageFromExtension(ext string) string {
	switch strings.ToLower(ext) {
	case ".go":
		return "Go"
	case ".php":
		return "PHP"
	case ".js", ".mjs", ".cjs":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	case ".py":
		return "Python"
	case ".rb":
		return "Ruby"
	case ".java":
		return "Java"
	case ".cs":
		return "C#"
	case ".rs":
		return "Rust"
	case ".html", ".htm":
		return "HTML"
	case ".css", ".scss", ".sass":
		return "CSS"
	case ".sql":
		return "SQL"
	case ".sh", ".bash":
		return "Shell"
	case ".yml", ".yaml":
		return "YAML"
	case ".json":
		return "JSON"
	default:
		return ""
	}
}

// Kept here for later source inspection helpers.
func lineCount(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0

	for scanner.Scan() {
		count++
	}

	return count, scanner.Err()
}
