package features

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type testEvidence map[string]bool

func (e testEvidence) Exists(id string) bool { return e[id] }

func TestSubmitSchemaIsValidAndRequiresObjectFindings(t *testing.T) {
	if !json.Valid(Task().SubmitSchema) {
		t.Fatal("feature submit schema is invalid JSON")
	}
	var schema struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(Task().SubmitSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["findings"].Type != "object" {
		t.Fatalf("findings schema type is %q", schema.Properties["findings"].Type)
	}
}

func TestValidateResultAcceptsEmptyTree(t *testing.T) {
	if err := validateResult(
		resultWithFindings(t, Findings{Features: []Node{}}),
		testEvidence{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateResultAcceptsModuleFeatureActionHierarchy(t *testing.T) {
	if err := validateResultWithReferences(
		resultWithFindings(t, validFindings()),
		testEvidence{"ev_feature": true},
		validReferences(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateResultRejectsDuplicateIDs(t *testing.T) {
	findings := validFindings()
	findings.Features = append(findings.Features, findings.Features[0])
	err := validateResultWithReferences(
		resultWithFindings(t, findings),
		testEvidence{"ev_feature": true},
		validReferences(),
	)
	assertValidationError(t, err, "duplicate feature ID")
}

func TestValidateResultRejectsActionWithChildren(t *testing.T) {
	findings := validFindings()
	action := &findings.Features[0].Children[0].Children[0]
	action.Children = []Node{validAction("projects.manage.create.extra")}
	err := validateResultWithReferences(
		resultWithFindings(t, findings),
		testEvidence{"ev_feature": true},
		validReferences(),
	)
	assertValidationError(t, err, "cannot have children")
}

func TestValidateResultRejectsUnknownCanonicalReferences(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Node)
		expected string
	}{
		{"entity", func(n *Node) { n.EntityIDs = []string{"missing"} }, "unknown entity"},
		{"interface", func(n *Node) { n.InterfaceIDs = []string{"missing"} }, "unknown interface"},
		{"integration as interface", func(n *Node) { n.InterfaceIDs = []string{"integration.stripe"} }, "uses integration"},
		{"role", func(n *Node) { n.Access.RoleIDs = []string{"missing"} }, "unknown role"},
		{"permission", func(n *Node) { n.Access.PermissionIDs = []string{"missing"} }, "unknown permission"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := validFindings()
			test.mutate(&findings.Features[0].Children[0].Children[0])
			err := validateResultWithReferences(
				resultWithFindings(t, findings),
				testEvidence{"ev_feature": true},
				validReferences(),
			)
			assertValidationError(t, err, test.expected)
		})
	}
}

func TestValidateResultRejectsEvidenceAndConfidenceErrors(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Node)
		expected string
	}{
		{"missing evidence", func(n *Node) { n.EvidenceIDs = nil }, "no evidence"},
		{"invalid evidence", func(n *Node) { n.EvidenceIDs = []string{"ev_missing"} }, "unknown evidence ID"},
		{"zero confidence", func(n *Node) { n.Confidence = 0 }, "must be greater than 0"},
		{"high confidence", func(n *Node) { n.Confidence = 1.1 }, "must be greater than 0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := validFindings()
			test.mutate(&findings.Features[0])
			err := validateResultWithReferences(
				resultWithFindings(t, findings),
				testEvidence{"ev_feature": true},
				validReferences(),
			)
			assertValidationError(t, err, test.expected)
		})
	}
}

func TestValidateResultRejectsNonHierarchicalChildID(t *testing.T) {
	findings := validFindings()
	findings.Features[0].Children[0].ID = "tasks.manage"
	err := validateResultWithReferences(
		resultWithFindings(t, findings),
		testEvidence{"ev_feature": true},
		validReferences(),
	)
	assertValidationError(t, err, "not within parent hierarchy")
}

func TestRunScopedPriorEvidenceCanBeReused(t *testing.T) {
	findings := validFindings()
	forEachNode(findings.Features, func(node *Node) {
		node.EvidenceIDs = []string{"ev_prior_surface"}
	})
	if err := validateResultWithReferences(
		resultWithFindings(t, findings),
		testEvidence{"ev_prior_surface": true},
		validReferences(),
	); err != nil {
		t.Fatalf("prior run-scoped evidence was not reusable: %v", err)
	}
}

func TestCountsTopLevelModulesAndAllNodes(t *testing.T) {
	findings := validFindings()
	findings.Features = append(findings.Features, Node{
		ID: "information", Type: "module", Children: []Node{},
	})
	modules, nodes := Counts(&findings)
	if modules != 2 || nodes != 4 {
		t.Fatalf("got %d top-level modules and %d total nodes", modules, nodes)
	}
}

func TestPromptDistinguishesSemanticFeaturesFromSurfaceAndIntegrations(t *testing.T) {
	prompt := Task().Objective + "\n" + Task().Instructions
	for _, expected := range []string{
		"semantic layer above Technical Surface",
		"Do not create one feature per route",
		"Do not mechanically mirror route, controller, model, or template trees",
		"Integrations are not interfaces",
		"integration IDs must never appear in interface_ids",
		"Primarily reason from those existing structured findings",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("feature prompt does not contain %q", expected)
		}
	}
}

func TestFeatureTaskUsesToolFreeStructuredFinalization(t *testing.T) {
	requests := make(chan llm.ChatRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request llm.ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- request
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(llm.ChatResponse{
			Choices: []llm.Choice{{Message: llm.Message{
				Role:    "assistant",
				Content: `{"status":"completed","summary":"done","findings":{"features":[]}}`,
			}}},
		})
	}))
	defer server.Close()

	runner := investigation.NewRunner(
		llm.NewClient(server.URL, "", "test-model"),
		tools.NewRegistry(),
		evidence.NewStore(t.TempDir()),
	)
	task := Task()
	task.Context = json.RawMessage(`{"entities":[{"id":"project"}]}`)
	task.ValidateResult = nil
	task.Budget.MaxTurns = 1
	task.Budget.FinalizeTurns = 1
	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	request := <-requests
	if len(request.Tools) != 0 || request.ToolChoice != nil {
		t.Fatalf("structured finalization exposed tools: %#v", request)
	}
	if request.ResponseFormat == nil || request.ResponseFormat.Type != "json_schema" {
		t.Fatalf("missing JSON Schema response format: %#v", request.ResponseFormat)
	}
	if investigation.JSONValueKind(request.ResponseFormat.JSONSchema.Schema) != "object" {
		t.Fatal("feature schema was not serialized as an object")
	}
	if !strings.Contains(request.Messages[0].Content, `"id": "project"`) {
		t.Fatal("structured prior findings were not included")
	}
}

func validFindings() Findings {
	return Findings{Features: []Node{{
		ID:          "projects",
		Name:        "Projects",
		Type:        "module",
		Description: "Project functionality.",
		Access: Access{
			Authentication: "required",
			RoleIDs:        []string{"admin"},
			PermissionIDs:  []string{"project.manage"},
		},
		EntityIDs:    []string{"project"},
		InterfaceIDs: []string{},
		Children: []Node{{
			ID:          "projects.manage",
			Name:        "Project Management",
			Type:        "feature",
			Description: "Manage projects.",
			Access: Access{
				Authentication: "required",
				RoleIDs:        []string{"admin"},
				PermissionIDs:  []string{"project.manage"},
			},
			EntityIDs:    []string{"project"},
			InterfaceIDs: []string{},
			Children: []Node{
				validAction("projects.manage.create"),
			},
			Confidence:  0.95,
			EvidenceIDs: []string{"ev_feature"},
		}},
		Confidence:  0.95,
		EvidenceIDs: []string{"ev_feature"},
	}}}
}

func validAction(id string) Node {
	return Node{
		ID:          id,
		Name:        "Create Project",
		Type:        "action",
		Description: "Create a project.",
		Access: Access{
			Authentication: "required",
			RoleIDs:        []string{"admin"},
			PermissionIDs:  []string{"project.manage"},
		},
		EntityIDs:    []string{"project"},
		InterfaceIDs: []string{"project.create"},
		Children:     []Node{},
		Confidence:   0.95,
		EvidenceIDs:  []string{"ev_feature"},
	}
}

func validReferences() priorReferences {
	return referencesFromFindings(
		&authorization.Findings{
			Roles:       []authorization.Role{{ID: "admin"}},
			Permissions: []authorization.Permission{{ID: "project.manage"}},
		},
		&entities.Findings{Entities: []entities.Entity{{ID: "project"}}},
		&surface.Findings{
			Interfaces:   []surface.Interface{{ID: "project.create"}},
			Integrations: []surface.Integration{{ID: "integration.stripe"}},
		},
	)
}

func resultWithFindings(t *testing.T, findings Findings) *investigation.Result {
	t.Helper()
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	return &investigation.Result{
		Status: "completed", Summary: "done", Findings: raw,
	}
}

func assertValidationError(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected error containing %q, got %v", expected, err)
	}
}

func forEachNode(nodes []Node, visit func(*Node)) {
	for i := range nodes {
		visit(&nodes[i])
		forEachNode(nodes[i].Children, visit)
	}
}
