package coretests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type Session struct {
	Root      string
	Pack      *testsmodel.TestPack
	Execution *testsmodel.Execution
	Baseline  *testsmodel.Baseline
	redactor  *runtimeverify.Redactor
}

type ArtifactPaths struct {
	Pack      string
	Markdown  string
	Execution string
	Baseline  string
	Evidence  string
}

func NewSession(
	sourceRunRoot, identity string,
	application *model.Application,
	runtime *runtimeverify.Runtime,
	redactor *runtimeverify.Redactor,
) (*Session, error) {
	packID := id.New("testpack")
	root := filepath.Join(sourceRunRoot, "tests", packID)
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if redactor == nil {
		redactor = runtimeverify.NewRedactor()
	}
	return &Session{
		Root: root, redactor: redactor,
		Pack: &testsmodel.TestPack{
			SchemaVersion: testsmodel.SchemaVersion, TestPackID: packID,
			SourceRunID: application.Metadata.RunID, RuntimeRunID: runtime.RuntimeID,
			GitCommit: application.Metadata.Source.GitCommit, Identity: identity,
			GeneratedAt: now, Tests: []testsmodel.TestCase{},
		},
		Execution: &testsmodel.Execution{
			SchemaVersion: testsmodel.SchemaVersion, TestPackID: packID,
			SourceRunID: application.Metadata.RunID, RuntimeRunID: runtime.RuntimeID,
			GitCommit: application.Metadata.Source.GitCommit, Identity: identity,
			StartedAt: now, Results: []testsmodel.CandidateResult{},
		},
	}, nil
}

func (s *Session) Complete(results []testsmodel.CandidateResult) {
	s.Execution.Results = append([]testsmodel.CandidateResult(nil), results...)
	for index := range s.Execution.Results {
		result := &s.Execution.Results[index]
		result.Reason = s.redactor.String(result.Reason)
		result.WorkflowFailure = s.redactor.String(result.WorkflowFailure)
		result.CleanupFailure = s.redactor.String(result.CleanupFailure)
		for key, value := range result.Values {
			result.Values[key] = s.redactor.String(value)
		}
		for ownedIndex := range result.OwnedObjects {
			for key, value := range result.OwnedObjects[ownedIndex].GeneratedFields {
				result.OwnedObjects[ownedIndex].GeneratedFields[key] = s.redactor.String(value)
			}
		}
	}
	s.Execution.CompletedAt = time.Now().UTC()
	s.Execution.Summary = summarizeResults(results)
	verified := make(map[string]int, len(s.Pack.Tests))
	for index := range s.Pack.Tests {
		verified[s.Pack.Tests[index].ID] = index
	}
	for _, result := range s.Execution.Results {
		if result.Status == testsmodel.StatusPassed {
			test := result.Candidate
			testsmodel.NormalizeTest(&test)
			if index, exists := verified[test.ID]; exists {
				s.Pack.Tests[index] = test
			} else {
				verified[test.ID] = len(s.Pack.Tests)
				s.Pack.Tests = append(s.Pack.Tests, test)
			}
		}
	}
	sort.Slice(s.Pack.Tests, func(i, j int) bool { return s.Pack.Tests[i].ID < s.Pack.Tests[j].ID })
	sort.Slice(s.Execution.Results, func(i, j int) bool {
		return s.Execution.Results[i].Candidate.ID < s.Execution.Results[j].Candidate.ID
	})
	if len(s.Pack.Tests) > 0 {
		ids := make([]string, 0, len(s.Pack.Tests))
		for _, test := range s.Pack.Tests {
			ids = append(ids, test.ID)
		}
		s.Baseline = &testsmodel.Baseline{
			SchemaVersion: testsmodel.SchemaVersion, SourceRunID: s.Pack.SourceRunID,
			RuntimeRunID: s.Pack.RuntimeRunID, GitCommit: s.Pack.GitCommit,
			TestPackID: s.Pack.TestPackID, VerifiedTestIDs: ids,
		}
	}
}

func (s *Session) SeedVerifiedTests(pack *testsmodel.TestPack) {
	if pack == nil {
		return
	}
	s.Pack.Tests = append([]testsmodel.TestCase(nil), pack.Tests...)
}

func (s *Session) Write(application *model.Application) (ArtifactPaths, error) {
	if err := testsmodel.ValidatePack(s.Pack, application); err != nil {
		return ArtifactPaths{}, err
	}
	paths := ArtifactPaths{
		Pack:      filepath.Join(s.Root, "core-tests.json"),
		Markdown:  filepath.Join(s.Root, "core-tests.md"),
		Execution: filepath.Join(s.Root, "execution.json"),
		Evidence:  filepath.Join(s.Root, "evidence.jsonl"),
	}
	values := []struct {
		path  string
		value any
	}{
		{paths.Pack, s.Pack},
		{paths.Execution, s.Execution},
	}
	for _, value := range values {
		data, err := json.MarshalIndent(value.value, "", "  ")
		if err != nil {
			return ArtifactPaths{}, err
		}
		if err := atomicWrite(value.path, append(data, '\n')); err != nil {
			return ArtifactPaths{}, err
		}
	}
	if err := atomicWrite(paths.Markdown, Markdown(s.Pack, s.Execution)); err != nil {
		return ArtifactPaths{}, err
	}
	if s.Baseline != nil {
		paths.Baseline = filepath.Join(s.Root, "baseline.json")
		data, err := json.MarshalIndent(s.Baseline, "", "  ")
		if err != nil {
			return ArtifactPaths{}, err
		}
		if err := atomicWrite(paths.Baseline, append(data, '\n')); err != nil {
			return ArtifactPaths{}, err
		}
	}
	return paths, nil
}

func summarizeResults(results []testsmodel.CandidateResult) testsmodel.ExecutionSummary {
	summary := testsmodel.ExecutionSummary{Candidates: len(results)}
	for _, result := range results {
		switch result.Status {
		case testsmodel.StatusPassed:
			summary.Passed++
		case testsmodel.StatusBlocked:
			summary.Blocked++
		case testsmodel.StatusFailed:
			summary.Failed++
		case testsmodel.StatusCleanupFailed:
			summary.CleanupFailed++
		case testsmodel.StatusUnresolved:
			summary.Unresolved++
		case testsmodel.StatusNotAttempted, testsmodel.StatusCandidate:
			summary.NotAttempted++
		}
	}
	return summary
}

func Markdown(pack *testsmodel.TestPack, execution *testsmodel.Execution) []byte {
	var out bytes.Buffer
	fmt.Fprintln(&out, "# Core Test Pack")
	fmt.Fprintf(&out, "\n- Source commit: `%s`\n", pack.GitCommit)
	fmt.Fprintf(&out, "- Runtime: `%s`\n", pack.RuntimeRunID)
	fmt.Fprintf(&out, "- Identity: `%s`\n", pack.Identity)
	fmt.Fprintln(&out, "\n## Summary")
	fmt.Fprintf(&out, "\n- Candidates: %d\n", execution.Summary.Candidates)
	fmt.Fprintf(&out, "- Passed: %d\n", execution.Summary.Passed)
	fmt.Fprintf(&out, "- Blocked: %d\n", execution.Summary.Blocked)
	fmt.Fprintf(&out, "- Failed: %d\n", execution.Summary.Failed)
	fmt.Fprintf(&out, "- Cleanup failed: %d\n", execution.Summary.CleanupFailed)
	fmt.Fprintf(&out, "- Unresolved: %d\n", execution.Summary.Unresolved)
	fmt.Fprintln(&out, "\n## Verified Tests")
	for _, result := range execution.Results {
		if result.Status == testsmodel.StatusPassed {
			fmt.Fprintf(&out, "\n### %s\n\nPASS — `%s`\n", result.Candidate.Name, result.Candidate.ID)
		}
	}
	fmt.Fprintln(&out, "\n## Blocked Mutating Test Candidates")
	blocked := 0
	for _, result := range execution.Results {
		if result.Status == testsmodel.StatusBlocked && result.Candidate.Safety.Mutating {
			blocked++
			fmt.Fprintf(&out, "\n### %s\n\nBlocked — %s\n", result.Candidate.Name, result.Reason)
		}
	}
	if blocked == 0 {
		fmt.Fprintln(&out, "\nNone.")
	}
	fmt.Fprintln(&out, "\n## Failures / Unresolved")
	issues := 0
	for _, result := range execution.Results {
		if result.Status == testsmodel.StatusFailed || result.Status == testsmodel.StatusCleanupFailed ||
			result.Status == testsmodel.StatusUnresolved {
			issues++
			fmt.Fprintf(&out, "\n- `%s` — `%s`: %s\n", result.Candidate.ID, result.Status, result.Reason)
		}
	}
	if issues == 0 {
		fmt.Fprintln(&out, "\nNone.")
	}
	return out.Bytes()
}

func atomicWrite(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".core-tests-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
