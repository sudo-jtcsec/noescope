package repository

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SearchOptions struct {
	Query         string
	Path          string
	Regex         bool
	CaseSensitive bool
	FileGlob      string
	MaxResults    int
	ContextLines  int
}

type SearchMatch struct {
	Path      string       `json:"path"`
	Line      int          `json:"line"`
	StartLine int          `json:"start_line"`
	EndLine   int          `json:"end_line"`
	Lines     []SourceLine `json:"lines"`
}

type SearchResult struct {
	Query     string        `json:"query"`
	Matches   []SearchMatch `json:"matches"`
	Truncated bool          `json:"truncated"`
}

func (r *Repository) Search(opts SearchOptions) (*SearchResult, error) {
	if opts.Query == "" {
		return nil, fmt.Errorf("search query is required")
	}

	if opts.Path == "" {
		opts.Path = "."
	}

	if opts.MaxResults <= 0 {
		opts.MaxResults = 50
	}

	if opts.MaxResults > 500 {
		opts.MaxResults = 500
	}

	if opts.ContextLines < 0 {
		opts.ContextLines = 0
	}

	resolved, err := r.Resolve(opts.Path)
	if err != nil {
		return nil, err
	}

	var compiled *regexp.Regexp

	if opts.Regex {
		pattern := opts.Query

		if !opts.CaseSensitive {
			pattern = "(?i)" + pattern
		}

		compiled, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
	}

	result := &SearchResult{
		Query: opts.Query,
	}

	stop := false

	err = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || stop {
			return nil
		}

		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(r.Root, path)
		if err != nil {
			return nil
		}

		relSlash := filepath.ToSlash(rel)

		if opts.FileGlob != "" {
			matchedName, _ := filepath.Match(opts.FileGlob, entry.Name())
			matchedPath, _ := filepath.Match(opts.FileGlob, relSlash)

			if !matchedName && !matchedPath {
				return nil
			}
		}

		binary, err := isBinaryFile(path)
		if err != nil || binary {
			return nil
		}

		lines, err := readAllSearchableLines(path)
		if err != nil {
			return nil
		}

		for i, line := range lines {
			matched := false

			if opts.Regex {
				matched = compiled.MatchString(line)
			} else if opts.CaseSensitive {
				matched = strings.Contains(line, opts.Query)
			} else {
				matched = strings.Contains(
					strings.ToLower(line),
					strings.ToLower(opts.Query),
				)
			}

			if !matched {
				continue
			}

			start := i - opts.ContextLines
			if start < 0 {
				start = 0
			}

			end := i + opts.ContextLines
			if end >= len(lines) {
				end = len(lines) - 1
			}

			match := SearchMatch{
				Path:      relSlash,
				Line:      i + 1,
				StartLine: start + 1,
				EndLine:   end + 1,
			}

			for n := start; n <= end; n++ {
				match.Lines = append(match.Lines, SourceLine{
					Number: n + 1,
					Text:   lines[n],
				})
			}

			result.Matches = append(result.Matches, match)

			if len(result.Matches) >= opts.MaxResults {
				result.Truncated = true
				stop = true
				break
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("search repository: %w", err)
	}

	return result, nil
}

func readAllSearchableLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}
