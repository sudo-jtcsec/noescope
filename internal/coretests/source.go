package coretests

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type LoadedRuntime struct {
	Root    string
	Runtime *runtimeverify.Runtime
	Path    string
}

func LoadBestVerifiedPack(
	sourceRunRoot string,
	application *model.Application,
	runtimeID string,
) (*testsmodel.TestPack, error) {
	root := filepath.Join(sourceRunRoot, "tests")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list Core Test packs: %w", err)
	}
	type candidate struct{ pack testsmodel.TestPack }
	candidates := []candidate{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, entry.Name(), "core-tests.json"))
		if err != nil {
			continue
		}
		var pack testsmodel.TestPack
		if json.Unmarshal(raw, &pack) != nil || pack.SourceRunID != application.Metadata.RunID ||
			pack.GitCommit != application.Metadata.Source.GitCommit || pack.RuntimeRunID != runtimeID ||
			testsmodel.ValidatePack(&pack, application) != nil {
			continue
		}
		candidates = append(candidates, candidate{pack: pack})
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i].pack.Tests) != len(candidates[j].pack.Tests) {
			return len(candidates[i].pack.Tests) > len(candidates[j].pack.Tests)
		}
		if !candidates[i].pack.GeneratedAt.Equal(candidates[j].pack.GeneratedAt) {
			return candidates[i].pack.GeneratedAt.After(candidates[j].pack.GeneratedAt)
		}
		return candidates[i].pack.TestPackID > candidates[j].pack.TestPackID
	})
	pack := candidates[0].pack
	return &pack, nil
}

func LoadCompletedRuntime(sourceRunRoot, runtimeID string, application *model.Application) (*LoadedRuntime, error) {
	root := filepath.Join(sourceRunRoot, "runtime")
	if runtimeID != "" {
		return loadRuntime(filepath.Join(root, runtimeID), application)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("list runtime runs: %w", err)
	}
	type candidate struct {
		root      string
		completed time.Time
		id        string
	}
	candidates := []candidate{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		loaded, err := loadRuntime(filepath.Join(root, entry.Name()), application)
		if err == nil {
			candidates = append(candidates, candidate{loaded.Root, loaded.Runtime.CompletedAt, entry.Name()})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].completed.Equal(candidates[j].completed) {
			return candidates[i].id > candidates[j].id
		}
		return candidates[i].completed.After(candidates[j].completed)
	})
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no compatible completed runtime run exists")
	}
	return loadRuntime(candidates[0].root, application)
}

func loadRuntime(root string, application *model.Application) (*LoadedRuntime, error) {
	path := filepath.Join(root, "runtime.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtime artifact: %w", err)
	}
	var runtime runtimeverify.Runtime
	if err := json.Unmarshal(raw, &runtime); err != nil {
		return nil, fmt.Errorf("decode runtime artifact: %w", err)
	}
	if runtime.Status != runtimeverify.RunStatusCompleted {
		return nil, fmt.Errorf("runtime %q is not completed", runtime.RuntimeID)
	}
	evidence, err := loadEvidenceIDs(filepath.Join(root, "evidence.jsonl"))
	if err != nil {
		return nil, err
	}
	if err := runtimeverify.ValidateRuntime(application, &runtime, evidence); err != nil {
		return nil, fmt.Errorf("validate runtime %q: %w", runtime.RuntimeID, err)
	}
	return &LoadedRuntime{Root: root, Runtime: &runtime, Path: path}, nil
}

type evidenceIDs map[string]struct{}

func (ids evidenceIDs) Exists(id string) bool {
	_, ok := ids[id]
	return ok
}

func loadEvidenceIDs(path string) (evidenceIDs, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read runtime evidence: %w", err)
	}
	defer file.Close()
	ids := evidenceIDs{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var record struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.ID == "" {
			return nil, fmt.Errorf("decode runtime evidence")
		}
		ids[record.ID] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
