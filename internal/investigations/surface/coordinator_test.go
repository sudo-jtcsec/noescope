package surface

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
)

func TestApplicableCategoriesUseValidatedArchitectureSignals(t *testing.T) {
	findings := allCategoryArchitecture()
	got := ApplicableCategories(findings)
	want := []Category{
		CategoryWeb, CategoryAPI, CategoryCLI,
		CategoryBackground, CategoryIntegrations,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected categories: got %v want %v", got, want)
	}

	unsupported := &architecture.Findings{
		Entrypoints: []architecture.Entrypoint{{
			Path: "index.php", Type: "web", Confidence: 0,
		}},
		Databases: []architecture.Technology{{Name: "SQLite", Confidence: 0}},
	}
	if got := ApplicableCategories(unsupported); len(got) != 0 {
		t.Fatalf("zero-confidence signals made categories applicable: %v", got)
	}
}

func TestApplicableCategoriesHonorTypedEntrypointsAndExternalInterfaces(t *testing.T) {
	findings := &architecture.Findings{
		Entrypoints: []architecture.Entrypoint{
			{Path: "rpc.php", Type: "api", Purpose: "API route", Confidence: 1},
			{Path: "maintenance.php", Type: "script", Purpose: "maintenance", Confidence: 1},
		},
		ExternalInterfaces: []architecture.Technology{{
			Name: "OpenAI-compatible LLM HTTP API", Confidence: 1,
		}},
	}

	got := ApplicableCategories(findings)
	want := []Category{CategoryAPI, CategoryCLI, CategoryIntegrations}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected categories: got %v want %v", got, want)
	}
}

func TestCategoryCoordinatorExecutesApplicableTasksSerially(t *testing.T) {
	var executionOrder []string
	execute := func(
		_ context.Context,
		task investigation.Task,
	) (*investigation.Result, error) {
		executionOrder = append(executionOrder, task.ID)
		return emptySurfaceResult(t, investigation.UnresolvedQuestion{
			Question: "dynamic registrations remain", Priority: "low", Reason: "source is dynamic",
		}), nil
	}

	findings, result, err := runCategoryCoordinator(
		context.Background(),
		execute,
		testEvidence{},
		nil,
		json.RawMessage(`{"architecture":{"languages":["PHP"]},"entities":[{"id":"comment","name":"Comment"},{"id":"project","name":"Project"},{"id":"task","name":"Task"},{"id":"user","name":"User"}]}`),
		allCategoryArchitecture(),
		emptyReferences(),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"surface.web", "surface.api.group_1", "surface.api.group_2",
		"surface.api.group_3", "surface.cli",
		"surface.background", "surface.integrations",
	}
	if !reflect.DeepEqual(executionOrder, want) {
		t.Fatalf("categories did not execute serially: got %v want %v", executionOrder, want)
	}
	for category, coverage := range map[string]CategoryCoverage{
		"web":          findings.Coverage.Web,
		"api":          findings.Coverage.API,
		"cli":          findings.Coverage.CLI,
		"background":   findings.Coverage.Background,
		"integrations": findings.Coverage.Integrations,
	} {
		if !coverage.Applicable || coverage.Status != "completed" {
			t.Fatalf("unexpected %s coverage: %#v", category, coverage)
		}
	}
	if len(result.Unresolved) != len(want) {
		t.Fatalf("unresolved questions were not merged: %#v", result.Unresolved)
	}
	for i, unresolved := range result.Unresolved {
		category := strings.TrimPrefix(want[i], "surface.")
		category = strings.Split(category, ".")[0]
		if !strings.HasPrefix(unresolved.Question, category+": ") {
			t.Fatalf("unresolved category was not preserved: %#v", unresolved)
		}
	}
}

func TestValidatedCLIFindingsCanEnableBackgroundCategory(t *testing.T) {
	var executionOrder []string
	execute := func(
		_ context.Context,
		task investigation.Task,
	) (*investigation.Result, error) {
		executionOrder = append(executionOrder, task.ID)
		switch task.ID {
		case "surface.cli":
			return resultWithFindings(t, Findings{
				Interfaces: []Interface{concreteInterface(
					"cli.worker", "cli_command", InterfaceLocator{Command: "cli worker"}, "ev_cli",
				)}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{},
			}), nil
		case "surface.background":
			return resultWithFindings(t, Findings{
				Interfaces: []Interface{concreteInterface(
					"worker.queue", "worker", InterfaceLocator{Command: "cli worker"}, "ev_worker",
				)}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{},
			}), nil
		default:
			return emptySurfaceResult(t), nil
		}
	}
	architectureFindings := &architecture.Findings{Entrypoints: []architecture.Entrypoint{{
		Path: "cli", Type: "executable", Purpose: "console", Confidence: 1,
	}}}
	findings, _, err := runCategoryCoordinator(
		context.Background(), execute,
		testEvidence{"ev_cli": true, "ev_worker": true}, nil,
		json.RawMessage(`{"architecture":{},"entities":[]}`),
		architectureFindings, emptyReferences(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(executionOrder, []string{"surface.cli", "surface.background"}) {
		t.Fatalf("background was not serially enabled after CLI: %v", executionOrder)
	}
	if !findings.Coverage.Background.Applicable ||
		findings.Coverage.Background.Interfaces != 1 {
		t.Fatalf("unexpected adaptive background coverage: %#v", findings.Coverage.Background)
	}
}

func TestCategoryValidationRepresentsConcreteInvocationKinds(t *testing.T) {
	evidence := testEvidence{
		"ev_get": true, "ev_post": true, "ev_api": true,
		"ev_cli": true, "ev_job": true,
	}
	tests := []struct {
		name     string
		category Category
		findings Findings
	}{
		{
			name: "web GET and POST distinction", category: CategoryWeb,
			findings: Findings{Interfaces: []Interface{
				concreteInterface("web.project.create", "web_page", InterfaceLocator{Method: "GET", Path: "/project/create"}, "ev_get"),
				concreteInterface("web.project.create.submit", "form_action", InterfaceLocator{Method: "POST", Path: "/project/create"}, "ev_post"),
			}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{}},
		},
		{
			name: "JSON-RPC method", category: CategoryAPI,
			findings: Findings{Interfaces: []Interface{
				concreteInterface("api.jsonrpc", "api_endpoint", InterfaceLocator{
					Protocol: "jsonrpc", TransportPath: "/jsonrpc.php",
				}, "ev_api"),
				concreteInterface("api.task.create", "api_endpoint", InterfaceLocator{
					Protocol: "jsonrpc", MethodName: "createTask", TransportPath: "/jsonrpc.php",
				}, "ev_api"),
			}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{}},
		},
		{
			name: "CLI command", category: CategoryCLI,
			findings: Findings{Interfaces: []Interface{
				concreteInterface("cli.user.create", "cli_command", InterfaceLocator{Command: "cli user:create"}, "ev_cli"),
			}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{}},
		},
		{
			name: "background job", category: CategoryBackground,
			findings: Findings{Interfaces: []Interface{
				concreteInterface("job.notification.send", "scheduled_job", InterfaceLocator{Schedule: "cron", Command: "cli notification:send"}, "ev_job"),
			}, Integrations: []Integration{}, Handlers: []Handler{}, Relationships: []Relationship{}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCategoryResult(
				resultWithFindings(t, test.findings),
				evidence,
				emptyReferences(),
				test.category,
			)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatabaseLibraryIsNotAnExternalIntegration(t *testing.T) {
	internal := databaseIntegration("integration.picodb", "PicoDb Database", "PicoDb adapter")
	references := emptyReferences()
	references.internalLibraryNames = map[string]struct{}{"picodb": {}}
	err := validateResultWithReferences(
		resultWithFindings(t, Findings{
			Interfaces: []Interface{}, Integrations: []Integration{internal},
			Handlers: []Handler{}, Relationships: []Relationship{},
		}),
		testEvidence{"ev_database": true},
		references,
	)
	if err == nil || !strings.Contains(err.Error(), "internal library or abstraction") {
		t.Fatalf("expected internal abstraction rejection, got %v", err)
	}

	external := databaseIntegration("integration.postgresql", "PostgreSQL", "PostgreSQL database")
	err = validateResultWithReferences(
		resultWithFindings(t, Findings{
			Interfaces: []Interface{}, Integrations: []Integration{external},
			Handlers: []Handler{}, Relationships: []Relationship{},
		}),
		testEvidence{"ev_database": true},
		references,
	)
	if err != nil {
		t.Fatalf("external database provider should be representable: %v", err)
	}
}

func TestMergeCategoryFindingsDeduplicatesIdenticalInterfaces(t *testing.T) {
	item := concreteInterface(
		"api.jsonrpc", "api_endpoint",
		InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/jsonrpc.php"},
		"ev_transport",
	)
	first := categoryOutput{category: CategoryWeb, findings: &Findings{
		Interfaces: []Interface{item}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{},
	}, result: &investigation.Result{Status: "completed"}}

	merged, err := mergeCategoryFindings([]categoryOutput{first, first}, skippedCoverage())
	if err != nil {
		t.Fatal(err)
	}
	normalizeInterface(&item)
	if len(merged.Interfaces) != 1 || !reflect.DeepEqual(merged.Interfaces[0], item) {
		t.Fatalf("identical duplicate was not deduplicated: %#v", merged.Interfaces)
	}
}

func TestMergeCategoryFindingsCombinesCompatibleInterfaces(t *testing.T) {
	left := concreteInterface(
		"api.jsonrpc", "api_endpoint",
		InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/jsonrpc.php"},
		"ev_transport",
	)
	left.Description = "Accepts JSON-RPC requests."
	left.InputNames = []string{"payload"}
	left.EntityIDs = []string{"project"}
	left.Confidence = 0.8

	right := concreteInterface(
		"api.jsonrpc", "api_endpoint",
		InterfaceLocator{
			Method: "POST", Protocol: "jsonrpc", TransportPath: "/jsonrpc.php",
		},
		"ev_dispatch",
	)
	right.Description = "Dispatches registered API procedures."
	right.InputNames = []string{"method"}
	right.EntityIDs = []string{"task"}
	right.SourceComponents = []SourceComponent{{
		Path: "app/Api/ProcedureRegistry.php", Symbol: "dispatch",
	}}
	right.Access = &Access{
		Authentication: "required",
		RoleIDs:        []string{"app-user"},
		PermissionIDs:  []string{"api.access"},
		Confidence:     0.9,
		EvidenceIDs:    []string{"ev_access"},
	}
	right.Confidence = 0.95

	sharedHandler := func(interfaceID, evidenceID string) Handler {
		return Handler{
			ID: "handler.jsonrpc", Type: "method", Name: "JSON-RPC dispatcher",
			Path: "app/Api/ProcedureRegistry.php", Symbol: "dispatch",
			InterfaceIDs: []string{interfaceID}, Confidence: 0.9,
			EvidenceIDs: []string{evidenceID},
		}
	}
	first := categoryOutput{category: CategoryAPI, findings: &Findings{
		Interfaces: []Interface{left}, Integrations: []Integration{},
		Handlers:      []Handler{sharedHandler("api.jsonrpc", "ev_transport")},
		Relationships: []Relationship{},
	}}
	second := categoryOutput{category: CategoryAPI, findings: &Findings{
		Interfaces: []Interface{right}, Integrations: []Integration{},
		Handlers:      []Handler{sharedHandler("api.task.create", "ev_dispatch")},
		Relationships: []Relationship{},
	}}

	merged, err := mergeCategoryFindings(
		[]categoryOutput{first, second},
		skippedCoverage(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Interfaces) != 1 {
		t.Fatalf("compatible duplicate was not merged: %#v", merged.Interfaces)
	}
	got := merged.Interfaces[0]
	if got.Locator.Method != "POST" || got.Confidence != 0.95 ||
		!reflect.DeepEqual(got.InputNames, []string{"method", "payload"}) ||
		!reflect.DeepEqual(got.EntityIDs, []string{"project", "task"}) ||
		!reflect.DeepEqual(got.EvidenceIDs, []string{"ev_dispatch", "ev_transport"}) ||
		len(got.SourceComponents) != 2 || got.Access == nil ||
		!reflect.DeepEqual(got.Access.EvidenceIDs, []string{"ev_access"}) ||
		!strings.Contains(got.Description, left.Description) ||
		!strings.Contains(got.Description, right.Description) {
		t.Fatalf("complementary interface information was not preserved: %#v", got)
	}
	if len(merged.Handlers) != 1 || !reflect.DeepEqual(
		merged.Handlers[0].InterfaceIDs,
		[]string{"api.jsonrpc", "api.task.create"},
	) || !reflect.DeepEqual(
		merged.Handlers[0].EvidenceIDs,
		[]string{"ev_dispatch", "ev_transport"},
	) {
		t.Fatalf("compatible shared handler was not merged: %#v", merged.Handlers)
	}

	reversed, err := mergeCategoryFindings(
		[]categoryOutput{second, first},
		skippedCoverage(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged, reversed) {
		t.Fatalf("compatible merge depends on worker order:\n%#v\n%#v", merged, reversed)
	}
}

func TestMergeCategoryFindingsRejectsGenuinelyConflictingInterfaces(t *testing.T) {
	left := concreteInterface(
		"api.jsonrpc", "api_endpoint",
		InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/jsonrpc.php"},
		"ev_one",
	)
	right := left
	right.Locator.TransportPath = "/different-rpc.php"

	_, err := mergeCategoryFindings([]categoryOutput{
		{category: CategoryAPI, findings: &Findings{Interfaces: []Interface{left}}},
		{category: CategoryAPI, findings: &Findings{Interfaces: []Interface{right}}},
	}, skippedCoverage())
	if err == nil || !strings.Contains(err.Error(), "conflicting duplicate interface ID") ||
		!strings.Contains(err.Error(), "locator.transport_path differs") {
		t.Fatalf("expected identity conflict, got %v", err)
	}
}

func TestMergeCategoryFindingsAcceptsQualifiedAndShortHandlerSymbols(t *testing.T) {
	left := Handler{
		ID: "handler.taskfileprocedure", Type: "procedure", Name: "Task file procedure",
		Path:         "app/Api/Procedure/TaskFileProcedure.php",
		Symbol:       `Kanboard\Api\Procedure\TaskFileProcedure`,
		InterfaceIDs: []string{"api.jsonrpc"}, Confidence: 0.9,
		EvidenceIDs: []string{"ev_qualified"},
	}
	right := left
	right.Symbol = "TaskFileProcedure"
	right.InterfaceIDs = []string{"api.task.file"}
	right.EvidenceIDs = []string{"ev_short"}

	merged, err := mergeCategoryFindings([]categoryOutput{
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{left}}},
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{right}}},
	}, skippedCoverage())
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Handlers) != 1 ||
		merged.Handlers[0].Symbol != left.Symbol ||
		!reflect.DeepEqual(merged.Handlers[0].InterfaceIDs, []string{"api.jsonrpc", "api.task.file"}) ||
		!reflect.DeepEqual(merged.Handlers[0].EvidenceIDs, []string{"ev_qualified", "ev_short"}) {
		t.Fatalf("qualified and short handler symbols were not merged: %#v", merged.Handlers)
	}

	reversed, err := mergeCategoryFindings([]categoryOutput{
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{right}}},
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{left}}},
	}, skippedCoverage())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged, reversed) {
		t.Fatalf("handler symbol merge depends on worker order:\n%#v\n%#v", merged, reversed)
	}
}

func TestMergeCategoryFindingsRejectsDifferentHandlerSymbols(t *testing.T) {
	left := Handler{
		ID: "handler.procedure", Type: "procedure", Name: "Procedure",
		Path: "app/Api/Procedure.php", Symbol: `Kanboard\Api\TaskProcedure`,
	}
	right := left
	right.Symbol = `Kanboard\Api\ProjectProcedure`

	_, err := mergeCategoryFindings([]categoryOutput{
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{left}}},
		{category: CategoryAPI, findings: &Findings{Handlers: []Handler{right}}},
	}, skippedCoverage())
	if err == nil || !strings.Contains(err.Error(), "conflicting duplicate handler ID") ||
		!strings.Contains(err.Error(), "symbol differs") {
		t.Fatalf("expected incompatible handler symbol conflict, got %v", err)
	}
}

func TestMergeCategoryFindingsPreservesNormalNonDuplicateMerge(t *testing.T) {
	project := concreteInterface(
		"web.project.list", "web_page",
		InterfaceLocator{Method: "GET", Path: "/projects"}, "ev_project",
	)
	task := concreteInterface(
		"web.task.list", "web_page",
		InterfaceLocator{Method: "GET", Path: "/tasks"}, "ev_task",
	)
	merged, err := mergeCategoryFindings([]categoryOutput{{
		category: CategoryWeb,
		findings: &Findings{
			Interfaces: []Interface{task, project}, Integrations: []Integration{},
			Handlers: []Handler{}, Relationships: []Relationship{},
		},
	}}, skippedCoverage())
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Interfaces) != 2 ||
		merged.Interfaces[0].ID != "web.project.list" ||
		merged.Interfaces[1].ID != "web.task.list" {
		t.Fatalf("normal merge changed or reordered records incorrectly: %#v", merged.Interfaces)
	}
}

func TestCategoryValidationNormalizesCompatibleDuplicateIDs(t *testing.T) {
	item := concreteInterface(
		"api.task.get", "api_endpoint",
		InterfaceLocator{Protocol: "jsonrpc", MethodName: "getTask", TransportPath: "/jsonrpc.php"},
		"ev_api",
	)
	result := resultWithFindings(t, Findings{
		Interfaces: []Interface{item, item}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{},
	})
	if err := validateCategoryResult(
		result,
		testEvidence{"ev_api": true},
		emptyReferences(),
		CategoryAPI,
	); err != nil {
		t.Fatal(err)
	}
	findings, err := decodeFindings(result.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings.Interfaces) != 1 {
		t.Fatalf("compatible duplicate was not normalized: %#v", findings.Interfaces)
	}
}

func TestCoordinatorPerformsGlobalReferenceValidationAfterMerge(t *testing.T) {
	execute := func(
		_ context.Context,
		_ investigation.Task,
	) (*investigation.Result, error) {
		item := concreteInterface(
			"web.project.list", "web_page",
			InterfaceLocator{Method: "GET", Path: "/projects"}, "ev_get",
		)
		return resultWithFindings(t, Findings{
			Interfaces: []Interface{item}, Integrations: []Integration{}, Handlers: []Handler{},
			Relationships: []Relationship{{
				Type: "navigation", FromInterfaceID: item.ID, ToInterfaceID: "web.missing",
				Description: "Invalid edge", Confidence: 0.9, EvidenceIDs: []string{"ev_get"},
			}},
		}), nil
	}
	architectureFindings := &architecture.Findings{Entrypoints: []architecture.Entrypoint{{
		Path: "index.php", Type: "web", Purpose: "front controller", Confidence: 1,
	}}}
	_, _, err := runCategoryCoordinator(
		context.Background(), execute, testEvidence{"ev_get": true}, nil,
		json.RawMessage(`{"architecture":{}}`), architectureFindings, emptyReferences(),
	)
	if err == nil || !strings.Contains(err.Error(), "unknown to interface") {
		t.Fatalf("expected merged reference validation failure, got %v", err)
	}
}

func TestIntegrationCategoryContextContainsOnlyCompactPriorSurfaceIDs(t *testing.T) {
	prior := &Findings{Interfaces: make([]Interface, 0, 500)}
	for i := 0; i < 500; i++ {
		prior.Interfaces = append(prior.Interfaces, Interface{
			ID:          fmt.Sprintf("web.route.r%d", i),
			Name:        strings.Repeat("verbose-name", 20),
			Description: strings.Repeat("verbose-description", 50),
		})
	}
	base := json.RawMessage(`{"architecture":{"languages":["PHP"]},"authentication":{"authentication_present":true}}`)
	projected, err := buildCategoryContext(base, CategoryIntegrations, prior)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(struct {
		Base  json.RawMessage `json:"prior_findings"`
		Prior *Findings       `json:"prior_surface"`
	}{base, prior})
	if len(projected)*5 >= len(canonical) {
		t.Fatalf("prior Surface projection was not substantially compacted: %d -> %d", len(canonical), len(projected))
	}
	text := string(projected)
	if strings.Contains(text, "verbose-description") || strings.Contains(text, "summary") ||
		strings.Contains(text, "chat history") {
		t.Fatalf("compact context leaked excluded content: %s", text)
	}
	if !strings.Contains(text, "web.route.r499") || !strings.Contains(text, `"languages":["PHP"]`) {
		t.Fatal("compact context omitted prior findings or canonical interface IDs")
	}
}

func TestCategoryPromptsAndBudgetsAreScoped(t *testing.T) {
	web := taskForCategory(CategoryWeb)
	if web.Budget.MaxTurns != 15 || web.Budget.MaxToolCalls != 120 ||
		!strings.Contains(web.Objective, "concrete inbound web routes") ||
		!strings.Contains(web.Instructions, "HTTP method whenever") {
		t.Fatalf("unexpected web task: %#v", web.Budget)
	}
	api := taskForCategory(CategoryAPI)
	if api.Budget.MaxTurns != 12 || api.Budget.MaxToolCalls != 100 ||
		!strings.Contains(api.Instructions, "method_name") {
		t.Fatalf("unexpected API task: %#v", api.Budget)
	}
	apiSpecs := categoryTaskSpecs(
		CategoryAPI,
		json.RawMessage(`{"entities":[{"id":"comment","name":"Comment"},{"id":"project","name":"Project"},{"id":"task","name":"Task"}]}`),
	)
	if len(apiSpecs) != 3 ||
		taskForCategorySpec(CategoryAPI, apiSpecs[0]).ID != "surface.api.group_1" ||
		taskForCategorySpec(CategoryAPI, apiSpecs[2]).ID != "surface.api.group_3" {
		t.Fatalf("unexpected API segmentation: %#v", apiSpecs)
	}
	for _, category := range []Category{CategoryCLI, CategoryBackground, CategoryIntegrations} {
		task := taskForCategory(category)
		if task.Budget.MaxTurns != 10 || task.Budget.MaxToolCalls != 80 {
			t.Fatalf("unexpected %s budget: %#v", category, task.Budget)
		}
	}
	if !strings.Contains(
		taskForCategory(CategoryIntegrations).Instructions,
		"database abstraction",
	) {
		t.Fatal("integration prompt does not distinguish abstractions from providers")
	}
}

func allCategoryArchitecture() *architecture.Findings {
	return &architecture.Findings{
		Entrypoints: []architecture.Entrypoint{
			{Path: "index.php", Type: "web", Purpose: "front controller", Confidence: 1},
			{Path: "jsonrpc.php", Type: "api", Purpose: "JSON-RPC API", Confidence: 1},
			{Path: "cli", Type: "executable", Purpose: "console commands", Confidence: 1},
		},
		Libraries: []architecture.Technology{{Name: "SimpleQueue", Confidence: 1}},
		Databases: []architecture.Technology{{Name: "PostgreSQL", Confidence: 1}},
	}
}

func emptyReferences() priorReferences {
	return priorReferences{
		entityIDs: map[string]struct{}{}, roleIDs: map[string]struct{}{},
		permissionIDs: map[string]struct{}{}, interfaceIDs: map[string]struct{}{},
		integrationIDs: map[string]struct{}{}, internalLibraryNames: map[string]struct{}{},
	}
}

func emptySurfaceResult(
	t *testing.T,
	unresolved ...investigation.UnresolvedQuestion,
) *investigation.Result {
	t.Helper()
	result := resultWithFindings(t, Findings{
		Interfaces: []Interface{}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{},
	})
	result.Unresolved = unresolved
	return result
}

func concreteInterface(
	id, interfaceType string,
	locator InterfaceLocator,
	evidenceID string,
) Interface {
	return Interface{
		ID: id, Type: interfaceType, Name: id, Description: "Concrete invocation point.",
		Locator: locator, SourceComponents: []SourceComponent{{Path: "app/routes.php"}},
		EntityIDs: []string{}, Confidence: 0.95, EvidenceIDs: []string{evidenceID},
	}
}

func databaseIntegration(id, name, locatorName string) Integration {
	return Integration{
		ID: id, Type: "database", Name: name, Description: "Database dependency.",
		Locator:        IntegrationLocator{Name: locatorName},
		Authentication: IntegrationAuthentication{Type: "unknown"},
		EntityIDs:      []string{}, SourceComponents: []SourceComponent{{Path: "app/Database.php"}},
		Confidence: 0.95, EvidenceIDs: []string{"ev_database"},
	}
}
