package features

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
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

func TestModuleDiscoveryAcceptsOnlyModuleScaffoldsWithConcreteAssignments(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	references := referencesFromFindings(nil, nil, surfaceFindings)
	task := moduleDiscoveryTask(json.RawMessage(`{}`), references, ConcreteCandidateInterfaceIDs(surfaceFindings))
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	result := resultWithFindings(t, Findings{Features: []Node{module}})
	if err := task.ValidateResult(result, testEvidence{"ev_feature": true}); err != nil {
		t.Fatal(err)
	}

	invalid := module
	invalid.Children = []Node{coordinatorAction("tasks.create", []string{"api.task.create"})}
	err := task.ValidateResult(
		resultWithFindings(t, Findings{Features: []Node{invalid}}),
		testEvidence{"ev_feature": true},
	)
	assertValidationError(t, err, "must not contain children")

	rootOnly := module
	rootOnly.InterfaceIDs = []string{"api.transport"}
	err = task.ValidateResult(
		resultWithFindings(t, Findings{Features: []Node{rootOnly}}),
		testEvidence{"ev_feature": true},
	)
	assertValidationError(t, err, "only root")
}

func TestModuleDiscoveryReportsAllInvalidCanonicalReferencesTogether(t *testing.T) {
	references := priorReferences{
		entityIDs:      map[string]struct{}{"task": {}},
		interfaceIDs:   map[string]struct{}{"api.task.getall": {}},
		integrationIDs: map[string]struct{}{},
		roleIDs:        map[string]struct{}{"app_user": {}},
		permissionIDs:  map[string]struct{}{"project_view": {}},
	}
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.getAll"})
	module.EntityIDs = []string{"subtask"}
	module.Access.RoleIDs = []string{"user"}
	module.Access.PermissionIDs = []string{"task_view"}

	err := validateModuleCanonicalReferences([]Node{module}, references)
	for _, want := range []string{
		`unknown entities ["subtask"]`,
		`unknown interfaces ["api.task.getAll"]`,
		`unknown roles ["user"]`,
		`unknown permissions ["task_view"]`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestCanonicalInterfaceCaseNormalizationIsUniqueAndStrict(t *testing.T) {
	nodes := []Node{{
		InterfaceIDs: []string{
			"api.swimlane.getActive",
			"api.task.missing",
			"API.COLLISION",
		},
	}}
	normalizeCanonicalInterfaceReferences(nodes, map[string]struct{}{
		"api.swimlane.getactive": {},
		"api.collision":          {},
		"API.Collision":          {},
	})
	want := []string{
		"api.swimlane.getactive",
		"api.task.missing",
		"API.COLLISION",
	}
	if !reflect.DeepEqual(nodes[0].InterfaceIDs, want) {
		t.Fatalf("normalized IDs = %v, want %v", nodes[0].InterfaceIDs, want)
	}
}

func TestCoordinatorExpandsModulesSeriallyInDeterministicOrder(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	tasks := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	administration := coordinatorModule(
		"administration", "Administration", []string{"cli.database.migration"},
	)
	var calls []string
	execute := func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		calls = append(calls, task.ID)
		var findings Findings
		switch task.ID {
		case "features.modules":
			findings.Features = []Node{tasks, administration}
		case "features.administration":
			if strings.Contains(string(task.Context), "api.task.create") {
				t.Fatal("module context contains unrelated task interface")
			}
			findings.Features = []Node{coordinatorAction(
				"administration.migrate", []string{"cli.database.migration"},
			)}
		case "features.tasks":
			if strings.Contains(string(task.Context), "cli.database.migration") {
				t.Fatal("module context contains unrelated CLI interface")
			}
			feature := coordinatorFeature("tasks.lifecycle", []string{"api.task.create"})
			feature.Children = []Node{coordinatorAction(
				"tasks.lifecycle.create", []string{"api.task.create"},
			)}
			findings.Features = []Node{feature}
		default:
			return nil, errors.New("unexpected task " + task.ID)
		}
		result := resultWithFindings(t, findings)
		if err := task.ValidateResult(result, testEvidence{"ev_feature": true}); err != nil {
			return nil, err
		}
		return result, nil
	}

	findings, _, err := runCoordinator(
		context.Background(), execute, testEvidence{"ev_feature": true}, nil,
		json.RawMessage(`{}`), &authentication.Findings{}, &authorization.Findings{},
		&entities.Findings{}, surfaceFindings, RunOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"features.modules", "features.administration", "features.tasks"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("module execution order = %v, want %v", calls, wantCalls)
	}
	if findings.Features[0].ID != "administration" ||
		findings.Features[1].Children[0].Children[0].ID != "tasks.lifecycle.create" {
		t.Fatalf("deterministic merge failed: %#v", findings)
	}
}

func TestModuleExpansionRequiresActionsOnlyForConcreteOperations(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	references := referencesFromFindings(nil, nil, surfaceFindings)
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	task := moduleExpansionTask(module, json.RawMessage(`{}`), references, surfaceFindings)
	err := task.ValidateResult(
		resultWithFindings(t, Findings{Features: []Node{}}),
		testEvidence{"ev_feature": true},
	)
	assertValidationError(t, err, "produced no action nodes")

	rootModule := coordinatorModule("transport", "Transport", []string{"api.transport"})
	rootTask := moduleExpansionTask(rootModule, json.RawMessage(`{}`), references, surfaceFindings)
	if err := rootTask.ValidateResult(
		resultWithFindings(t, Findings{Features: []Node{}}),
		testEvidence{"ev_feature": true},
	); err != nil {
		t.Fatalf("root-only module should allow no actions: %v", err)
	}
}

func TestModuleExpansionAllowsMultipleInterfacesForOneAction(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	module := coordinatorModule(
		"tasks", "Tasks", []string{"api.task.create", "cli.database.migration"},
	)
	action := coordinatorAction(
		"tasks.create", []string{"api.task.create", "cli.database.migration"},
	)
	task := moduleExpansionTask(
		module, json.RawMessage(`{}`), referencesFromFindings(nil, nil, surfaceFindings),
		surfaceFindings,
	)
	if err := task.ValidateResult(
		resultWithFindings(t, Findings{Features: []Node{action}}),
		testEvidence{"ev_feature": true},
	); err != nil {
		t.Fatal(err)
	}
}

func TestModuleContextRetainsAssignedConcreteInterfacesAndDeprioritizesRoot(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	module := coordinatorModule(
		"tasks", "Tasks", []string{"api.transport", "api.task.create"},
	)
	raw, _, projectedBytes, err := buildModuleContext(
		module, &authentication.Findings{}, &authorization.Findings{},
		&entities.Findings{}, surfaceFindings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if projectedBytes > maxModuleContextBytes {
		t.Fatalf("module projection too large: %d", projectedBytes)
	}
	var context moduleExpansionContext
	if err := json.Unmarshal(raw, &context); err != nil {
		t.Fatal(err)
	}
	if len(context.Interfaces) != 2 || context.Interfaces[0].ID != "api.task.create" ||
		context.Interfaces[1].ID != "api.transport" || !context.Interfaces[1].Root {
		t.Fatalf("unexpected module interface projection: %#v", context.Interfaces)
	}
}

func TestFeatureExpansionCheckpointsResumeWithoutModelCalls(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	runRoot := t.TempDir()
	options := RunOptions{
		RunRoot: runRoot, RepositoryCommit: "commit-one", Resume: false,
		FeatureAttempt: 1,
	}
	execute := coordinatorFixtureExecutor(t, module)
	if _, _, err := runCoordinator(
		context.Background(), execute, testEvidence{"ev_feature": true}, nil,
		json.RawMessage(`{}`), &authentication.Findings{}, &authorization.Findings{},
		&entities.Findings{}, surfaceFindings, options,
	); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"modules.json", "tasks.json"} {
		if _, err := os.Stat(filepath.Join(runRoot, "work", "features", name)); err != nil {
			t.Fatalf("missing Feature checkpoint %s: %v", name, err)
		}
	}
	options.Resume = true
	if _, _, err := runCoordinator(
		context.Background(),
		func(context.Context, investigation.Task) (*investigation.Result, error) {
			return nil, errors.New("model should not be called")
		},
		testEvidence{"ev_feature": true}, nil, json.RawMessage(`{}`),
		&authentication.Findings{}, &authorization.Findings{}, &entities.Findings{},
		surfaceFindings, options,
	); err != nil {
		t.Fatalf("resume did not reuse completed expansions: %v", err)
	}
}

func TestFeatureRerunDoesNotReuseEarlierAttemptCheckpoints(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	runRoot := t.TempDir()
	options := RunOptions{
		RunRoot: runRoot, RepositoryCommit: "commit-one", FeatureAttempt: 1,
	}
	if _, _, err := runCoordinator(
		context.Background(), coordinatorFixtureExecutor(t, module),
		testEvidence{"ev_feature": true}, nil, json.RawMessage(`{}`),
		&authentication.Findings{}, &authorization.Findings{}, &entities.Findings{},
		surfaceFindings, options,
	); err != nil {
		t.Fatal(err)
	}

	options.Resume = true
	options.FeatureAttempt = 2
	calls := 0
	execute := coordinatorFixtureExecutor(t, module)
	if _, _, err := runCoordinator(
		context.Background(), func(ctx context.Context, task investigation.Task) (*investigation.Result, error) {
			calls++
			return execute(ctx, task)
		}, testEvidence{"ev_feature": true}, nil, json.RawMessage(`{}`),
		&authentication.Findings{}, &authorization.Findings{}, &entities.Findings{},
		surfaceFindings, options,
	); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("rerun executed %d tasks, want module discovery and one expansion", calls)
	}
}

func TestFailedModuleExpansionIsNotCheckpointed(t *testing.T) {
	surfaceFindings := coordinatorSurfaceFixture()
	module := coordinatorModule("tasks", "Tasks", []string{"api.task.create"})
	runRoot := t.TempDir()
	execute := func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		if task.ID == "features.modules" {
			result := resultWithFindings(t, Findings{Features: []Node{module}})
			if err := task.ValidateResult(result, testEvidence{"ev_feature": true}); err != nil {
				return nil, err
			}
			return result, nil
		}
		return nil, errors.New("expansion failed")
	}
	_, _, err := runCoordinator(
		context.Background(), execute, testEvidence{"ev_feature": true}, nil,
		json.RawMessage(`{}`), &authentication.Findings{}, &authorization.Findings{},
		&entities.Findings{}, surfaceFindings, RunOptions{
			RunRoot: runRoot, RepositoryCommit: "commit-one", FeatureAttempt: 1,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "expansion failed") {
		t.Fatalf("expected expansion failure, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(runRoot, "work", "features", "modules.json")); err != nil {
		t.Fatalf("successful module discovery was not checkpointed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runRoot, "work", "features", "tasks.json")); !os.IsNotExist(err) {
		t.Fatalf("failed expansion was checkpointed: %v", err)
	}
}

func coordinatorFixtureExecutor(t *testing.T, module Node) taskExecutor {
	t.Helper()
	return func(_ context.Context, task investigation.Task) (*investigation.Result, error) {
		var findings Findings
		if task.ID == "features.modules" {
			findings.Features = []Node{module}
		} else {
			findings.Features = []Node{coordinatorAction(
				module.ID+".create", []string{"api.task.create"},
			)}
		}
		result := resultWithFindings(t, findings)
		if err := task.ValidateResult(result, testEvidence{"ev_feature": true}); err != nil {
			return nil, err
		}
		return result, nil
	}
}

func coordinatorSurfaceFixture() *surface.Findings {
	return &surface.Findings{Interfaces: []surface.Interface{
		{ID: "api.transport", Type: "api_endpoint", Name: "API transport",
			Locator: surface.InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/rpc"}},
		{ID: "api.task.create", Type: "api_endpoint", Name: "Create task",
			Locator: surface.InterfaceLocator{MethodName: "task.create", TransportPath: "/rpc"}},
		{ID: "cli.database.migration", Type: "cli_command", Name: "Database migration",
			Locator: surface.InterfaceLocator{Command: "database:migration"}},
	}}
}

func coordinatorModule(id, name string, interfaceIDs []string) Node {
	return Node{
		ID: id, Name: name, Type: "module", Description: name + " functionality.",
		Access:    Access{Authentication: "not_required", RoleIDs: []string{}, PermissionIDs: []string{}},
		EntityIDs: []string{}, InterfaceIDs: interfaceIDs, Children: []Node{},
		Confidence: 0.9, EvidenceIDs: []string{"ev_feature"},
	}
}

func coordinatorFeature(id string, interfaceIDs []string) Node {
	return Node{
		ID: id, Name: "Lifecycle", Type: "feature", Description: "Lifecycle operations.",
		Access:    Access{Authentication: "not_required", RoleIDs: []string{}, PermissionIDs: []string{}},
		EntityIDs: []string{}, InterfaceIDs: interfaceIDs, Children: []Node{},
		Confidence: 0.9, EvidenceIDs: []string{"ev_feature"},
	}
}

func coordinatorAction(id string, interfaceIDs []string) Node {
	return Node{
		ID: id, Name: "Create", Type: "action", Description: "Creates an item.",
		Access:    Access{Authentication: "not_required", RoleIDs: []string{}, PermissionIDs: []string{}},
		EntityIDs: []string{}, InterfaceIDs: interfaceIDs, Children: []Node{},
		Confidence: 0.9, EvidenceIDs: []string{"ev_feature"},
	}
}
