package surface

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

func TestSplitCategoryTaskSpecIsDeterministicHalfSplit(t *testing.T) {
	spec := apiTaskSpec(
		"group_3",
		[]string{"a", "b", "c", "d", "e"},
		false,
		0,
	)
	left, right := splitCategoryTaskSpec(CategoryAPI, spec)
	if left.suffix != "group_3.1" || right.suffix != "group_3.2" ||
		!reflect.DeepEqual(left.candidates, []string{"a", "b", "c"}) ||
		!reflect.DeepEqual(right.candidates, []string{"d", "e"}) {
		t.Fatalf("unexpected deterministic split: %#v %#v", left, right)
	}
}

func TestCategoryShardRecursivelySplitsOversizedResults(t *testing.T) {
	var calls []string
	execute := func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		calls = append(calls, task.ID)
		if task.ID == "surface.api.group_3" || task.ID == "surface.api.group_3.1" {
			return nil, testStructuredTooLarge()
		}
		return emptySurfaceResult(t), nil
	}

	completed, _, err := runTestShard(
		t,
		execute,
		apiTaskSpec("group_3", []string{"a", "b", "c", "d"}, false, 0),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"surface.api.group_3",
		"surface.api.group_3.1",
		"surface.api.group_3.1.1",
		"surface.api.group_3.1.2",
		"surface.api.group_3.2",
	}
	if completed != 3 || !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("unexpected recursive execution: completed=%d calls=%v", completed, calls)
	}
}

func TestCategoryShardStopsAtMaximumDepth(t *testing.T) {
	spec := apiTaskSpec(
		"group_3.2.2.2.2",
		[]string{"a", "b"},
		false,
		maxShardDepth,
	)
	_, _, err := runTestShard(
		t,
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return nil, testStructuredTooLarge()
		},
		spec,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "maximum shard depth") {
		t.Fatalf("expected bounded-depth failure, got %v", err)
	}
}

func TestCategoryShardSingleCandidateFailureIsTerminal(t *testing.T) {
	_, _, err := runTestShard(
		t,
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return nil, testStructuredTooLarge()
		},
		apiTaskSpec("group_3.2", []string{"activity"}, false, 1),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), `candidate "activity"`) {
		t.Fatalf("expected candidate-specific terminal failure, got %v", err)
	}
}

func TestCategoryShardChildrenUseSemanticMerge(t *testing.T) {
	execute := func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		if task.ID == "surface.api.group_3" {
			return nil, testStructuredTooLarge()
		}
		transport := concreteInterface(
			"api.jsonrpc", "api_endpoint",
			InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/jsonrpc.php"},
			"ev_"+task.ID,
		)
		transport.InputNames = []string{task.ID}
		return resultWithFindings(t, Findings{
			Interfaces: []Interface{transport}, Integrations: []Integration{},
			Handlers: []Handler{}, Relationships: []Relationship{},
		}), nil
	}
	completed, merged, err := runTestShard(
		t,
		execute,
		apiTaskSpec("group_3", []string{"a", "b"}, false, 0),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if completed != 2 || len(merged.Interfaces) != 1 ||
		len(merged.Interfaces[0].EvidenceIDs) != 2 ||
		len(merged.Interfaces[0].InputNames) != 2 {
		t.Fatalf("child results did not use semantic merge: %#v", merged.Interfaces)
	}
}

func TestSuccessfulShardCheckpointWrittenAndFailedShardNotCompleted(t *testing.T) {
	options := testRunOptions(t, false, "commit-one")
	store := newCheckpointStore(options)
	success := apiTaskSpec("group_1", []string{"a"}, true, 0)
	if _, _, err := runTestShard(
		t,
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return emptySurfaceResult(t), nil
		},
		success,
		store,
	); err != nil {
		t.Fatal(err)
	}
	successID := "surface.api.group_1"
	if _, err := os.Stat(store.path(successID, CategoryAPI)); err != nil {
		t.Fatalf("successful checkpoint was not written: %v", err)
	}
	if state := options.Manifest.Surface[successID]; state.Status != "completed" {
		t.Fatalf("successful shard state is %#v", state)
	}

	failed := apiTaskSpec("group_2", []string{"b"}, false, 0)
	if _, _, err := runTestShard(
		t,
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return nil, errors.New("model unavailable")
		},
		failed,
		store,
	); err == nil {
		t.Fatal("expected failed shard")
	}
	failedID := "surface.api.group_2"
	if _, err := os.Stat(store.path(failedID, CategoryAPI)); !os.IsNotExist(err) {
		t.Fatalf("failed shard unexpectedly wrote a checkpoint: %v", err)
	}
	if state := options.Manifest.Surface[failedID]; state.Status != "failed" {
		t.Fatalf("failed shard state is %#v", state)
	}
}

func TestGloballyConflictingShardIsNotMarkedCompleted(t *testing.T) {
	options := testRunOptions(t, false, "commit-one")
	store := newCheckpointStore(options)
	prior := concreteInterface(
		"shared.command", "cli_command",
		InterfaceLocator{Command: "shared"}, "ev_prior",
	)
	outputs := []categoryOutput{{category: CategoryCLI, findings: &Findings{
		Interfaces: []Interface{prior},
	}}}
	merged := &Findings{Interfaces: []Interface{prior}}
	execute := func(context.Context, investigation.Task) (*investigation.Result, error) {
		conflict := concreteInterface(
			"shared.command", "scheduled_job",
			InterfaceLocator{Command: "shared"}, "ev_conflict",
		)
		return resultWithFindings(t, Findings{
			Interfaces: []Interface{conflict}, Integrations: []Integration{},
			Handlers: []Handler{}, Relationships: []Relationship{},
		}), nil
	}

	_, err := executeCategoryShard(
		context.Background(), execute,
		testEvidence{"ev_prior": true, "ev_conflict": true}, nil,
		json.RawMessage(`{}`), CategoryBackground,
		categoryTaskSpec{}, emptyReferences(), Coverage{},
		store, &outputs, &merged,
	)
	if err == nil || !strings.Contains(err.Error(), "types differ") {
		t.Fatalf("expected global identity conflict, got %v", err)
	}
	state := options.Manifest.Surface["surface.background"]
	if state.Status != "failed" {
		t.Fatalf("globally conflicting shard state = %#v", state)
	}
	if _, err := os.Stat(store.path("surface.background", CategoryBackground)); !os.IsNotExist(err) {
		t.Fatalf("globally conflicting shard wrote checkpoint: %v", err)
	}
}

func TestResumeSkipsSuccessfulShardAndRerunsFailedShard(t *testing.T) {
	options := testRunOptions(t, false, "commit-one")
	store := newCheckpointStore(options)
	success := apiTaskSpec("group_1", []string{"a"}, true, 0)
	failed := apiTaskSpec("group_2", []string{"b"}, false, 0)
	if _, _, err := runTestShard(
		t,
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return emptySurfaceResult(t), nil
		},
		success,
		store,
	); err != nil {
		t.Fatal(err)
	}
	_ = store.setState("surface.api.group_2", runpkg.SurfaceShardState{
		Status: "failed", Category: string(CategoryAPI), Candidates: []string{"b"},
	})

	store.resume = true
	var calls []string
	execute := func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		calls = append(calls, task.ID)
		return emptySurfaceResult(t), nil
	}
	if _, _, err := runTestShard(t, execute, success, store); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runTestShard(t, execute, failed, store); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"surface.api.group_2"}) {
		t.Fatalf("resume executions were %v", calls)
	}
}

func TestResumeRejectsCheckpointCommitAndSchemaMismatch(t *testing.T) {
	options := testRunOptions(t, false, "commit-one")
	store := newCheckpointStore(options)
	spec := apiTaskSpec("group_1", []string{"a"}, true, 0)
	task := taskForCategorySpec(CategoryAPI, spec)
	if err := store.save(task, CategoryAPI, spec.candidates, emptySurfaceResult(t)); err != nil {
		t.Fatal(err)
	}

	wrongCommit := newCheckpointStore(RunOptions{
		RunRoot: options.RunRoot, RepositoryCommit: "commit-two", Resume: true,
		Manifest: options.Manifest,
	})
	if _, _, err := wrongCommit.load(task, CategoryAPI, spec.candidates); err == nil ||
		!strings.Contains(err.Error(), "commit mismatch") {
		t.Fatalf("expected checkpoint commit rejection, got %v", err)
	}

	path := store.path(task.ID, CategoryAPI)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint map[string]any
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint["schema_version"] = "obsolete"
	raw, _ = json.Marshal(checkpoint)
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	store.resume = true
	if _, _, err := store.load(task, CategoryAPI, spec.candidates); err == nil ||
		!strings.Contains(err.Error(), "incompatible schema version") {
		t.Fatalf("expected checkpoint schema rejection, got %v", err)
	}
}

func runTestShard(
	t *testing.T,
	execute taskExecutor,
	spec categoryTaskSpec,
	store *checkpointStore,
) (int, *Findings, error) {
	t.Helper()
	outputs := []categoryOutput{}
	merged := &Findings{
		Interfaces: []Interface{}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{},
	}
	completed, err := executeCategoryShard(
		context.Background(), execute, testEvidence{}, nil, json.RawMessage(`{}`),
		CategoryAPI, spec, emptyReferences(), skippedCoverage(), store,
		&outputs, &merged,
	)
	return completed, merged, err
}

func testStructuredTooLarge() error {
	return &investigation.StructuredOutputTooLarge{
		Metadata: investigation.StructuredOutputMetadata{Bytes: 1000},
		Limit:    100,
	}
}

func testRunOptions(t *testing.T, resume bool, commit string) RunOptions {
	t.Helper()
	runRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runRoot, "output"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := &runpkg.Run{
		SchemaVersion: runpkg.SchemaVersion, ID: "run_test", Command: "discover",
		RepositoryRoot: "/repository", RepositoryCommit: commit, Through: "surface",
		CompletedStages: []string{}, Surface: map[string]runpkg.SurfaceShardState{},
		Root: runRoot,
	}
	if err := runpkg.Save(manifest); err != nil {
		t.Fatal(err)
	}
	return RunOptions{
		RunRoot: runRoot, RepositoryCommit: commit, Resume: resume, Manifest: manifest,
	}
}
