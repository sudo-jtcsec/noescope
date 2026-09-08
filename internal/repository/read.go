package repository

import (
	"bufio"
	"fmt"
	"os"
)

const DefaultReadLines = 500
const MaxReadLines = 2000

type SourceLine struct {
	Number int    `json:"number"`
	Text   string `json:"text"`
}

type ReadResult struct {
	Path      string       `json:"path"`
	StartLine int          `json:"start_line"`
	EndLine   int          `json:"end_line"`
	Lines     []SourceLine `json:"lines"`
	HasMore   bool         `json:"has_more"`
}

func (r *Repository) ReadFile(path string, startLine, endLine int) (*ReadResult, error) {
	info, err := r.FileInfo(path)
	if err != nil {
		return nil, err
	}

	if info.Binary {
		return nil, fmt.Errorf("cannot read binary file: %s", path)
	}

	if startLine <= 0 {
		startLine = 1
	}

	if endLine <= 0 {
		endLine = startLine + DefaultReadLines - 1
	}

	if endLine < startLine {
		return nil, fmt.Errorf("end line must be >= start line")
	}

	if endLine-startLine+1 > MaxReadLines {
		endLine = startLine + MaxReadLines - 1
	}

	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	result := &ReadResult{
		Path:      info.Path,
		StartLine: startLine,
	}

	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		if lineNumber < startLine {
			continue
		}

		if lineNumber > endLine {
			result.HasMore = true
			break
		}

		result.Lines = append(result.Lines, SourceLine{
			Number: lineNumber,
			Text:   scanner.Text(),
		})

		result.EndLine = lineNumber
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if result.EndLine == 0 {
		result.EndLine = startLine - 1
	}

	return result, nil
}
