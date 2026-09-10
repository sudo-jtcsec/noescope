package surface

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
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type testEvidence map[string]bool

func (e testEvidence) Exists(id string) bool {
	return e[id]
}

func TestSubmitSchemaIsValidJSON(t *testing.T) {
	if !json.Valid(Task().SubmitSchema) {
		t.Fatal("surface submission schema is not valid JSON")
	}
}

func TestValidateResultRejectsStringEncodedFindingsWithUsefulError(t *testing.T) {
	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: json.RawMessage(`"{\"interfaces\":[]}"`),
	}

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"surface findings: expected object, got string",
	) {
		t.Fatalf("expected useful string-encoded findings error, got %v", err)
	}
}

func TestValidateResultRejectsStringInterfaceLocatorWithPath(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "interfaces": [{
        "locator": "noescope discover",
        "source_components": []
      }],
      "integrations": [],
      "handlers": [],
      "relationships": []
    }`))

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"surface findings field interfaces[0].locator: expected object, got string",
	) {
		t.Fatalf("expected interface locator path error, got %v", err)
	}
}

func TestValidateResultRejectsStringIntegrationLocatorWithPath(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "interfaces": [],
      "integrations": [{
        "locator": "https://llm.example.test",
        "authentication": {"type": "bearer"},
        "source_components": []
      }],
      "handlers": [],
      "relationships": []
    }`))

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"surface findings field integrations[0].locator: expected object, got string",
	) {
		t.Fatalf("expected integration locator path error, got %v", err)
	}
}

func TestValidateResultRejectsStringIntegrationAuthenticationWithPath(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "interfaces": [],
      "integrations": [{
        "locator": {"base_url": "configurable"},
        "authentication": "bearer",
        "source_components": []
      }],
      "handlers": [],
      "relationships": []
    }`))

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"surface findings field integrations[0].authentication: expected object, got string",
	) {
		t.Fatalf("expected integration authentication path error, got %v", err)
	}
}

func TestValidateResultAcceptsTypedLocatorsAndAuthentication(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	integration := validHTTPIntegration()

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{
			"ev_cli":         true,
			"ev_integration": true,
		},
	)
	if err != nil {
		t.Fatalf("expected typed surface objects to be valid, got %v", err)
	}
}

func TestValidateResultAcceptsEmptyInterfaceList(t *testing.T) {
	result := resultWithFindings(t, Findings{
		Interfaces:    []Interface{},
		Integrations:  []Integration{},
		Handlers:      []Handler{},
		Relationships: []Relationship{},
	})

	if err := validateResult(result, testEvidence{}); err != nil {
		t.Fatalf("expected empty surface findings to be valid, got %v", err)
	}
}

func TestValidateResultAcceptsEvidenceBackedCLICommand(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_cli": true},
	)
	if err != nil {
		t.Fatalf("expected evidence-backed CLI command to be valid, got %v", err)
	}
}

func TestValidateResultAcceptsEvidenceBackedHTTPIntegration(t *testing.T) {
	integration := validHTTPIntegration()

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_integration": true},
	)
	if err != nil {
		t.Fatalf("expected evidence-backed HTTP integration to be valid, got %v", err)
	}
}

func TestValidateResultRejectsIntegrationWithoutEvidence(t *testing.T) {
	integration := validHTTPIntegration()
	integration.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing integration evidence error, got %v", err)
	}
}

func TestValidateResultRejectsInvalidIntegrationAuthentication(t *testing.T) {
	integration := validHTTPIntegration()
	integration.Authentication.Type = "application_user"

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_integration": true},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid authentication type") {
		t.Fatalf("expected invalid integration authentication error, got %v", err)
	}
}

func TestValidateResultRejectsIntegrationWithUnknownEntity(t *testing.T) {
	integration := validHTTPIntegration()
	integration.EntityIDs = []string{"investigation"}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_integration": true},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown entity") {
		t.Fatalf("expected unknown integration entity error, got %v", err)
	}
}

func TestValidateResultRejectsInterfaceWithoutEvidence(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	item.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing interface evidence error, got %v", err)
	}
}

func TestValidateResultRejectsUndeclaredEntityReference(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	item.EntityIDs = []string{"assessment"}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_cli": true},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown entity") {
		t.Fatalf("expected unknown entity error, got %v", err)
	}
}

func TestValidateResultAcceptsEntityAndAccessReferencesFromContext(t *testing.T) {
	item := validCLIInterface("assessment.run", "noescope assess")
	item.EntityIDs = []string{"assessment"}
	item.Access = &Access{
		Authentication: "required",
		RoleIDs:        []string{"operator"},
		PermissionIDs:  []string{"assessment.run"},
		Confidence:     0.9,
		EvidenceIDs:    []string{"ev_access"},
	}

	err := validateResultWithReferences(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{
			"ev_cli":    true,
			"ev_access": true,
		},
		priorReferences{
			entityIDs:     map[string]struct{}{"assessment": {}},
			roleIDs:       map[string]struct{}{"operator": {}},
			permissionIDs: map[string]struct{}{"assessment.run": {}},
		},
	)
	if err != nil {
		t.Fatalf("expected validated prior references to be accepted, got %v", err)
	}
}

func TestCanonicalFindingsRejectUnknownReferencesIndependentlyOfContextView(
	t *testing.T,
) {
	references := referencesFromFindings(
		&authorization.Findings{
			Roles:       []authorization.Role{{ID: "admin"}},
			Permissions: []authorization.Permission{{ID: "project.manage"}},
		},
		&entities.Findings{
			Entities: []entities.Entity{{ID: "project"}},
		},
	)

	tests := []struct {
		name       string
		entityIDs  []string
		roleIDs    []string
		permission []string
		errorText  string
	}{
		{
			name:      "entity",
			entityIDs: []string{"made.up.entity"},
			errorText: "unknown entity",
		},
		{
			name:      "role",
			roleIDs:   []string{"made.up.role"},
			errorText: "unknown role",
		},
		{
			name:       "permission",
			permission: []string{"made.up.permission"},
			errorText:  "unknown permission",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := validCLIInterface("project.show", "kanboard project:show")
			item.EntityIDs = test.entityIDs
			if len(test.roleIDs) > 0 || len(test.permission) > 0 {
				item.Access = &Access{
					Authentication: "required",
					RoleIDs:        test.roleIDs,
					PermissionIDs:  test.permission,
					Confidence:     0.9,
					EvidenceIDs:    []string{"ev_access"},
				}
			}
			err := validateResultWithReferences(
				resultWithFindings(t, Findings{
					Interfaces:    []Interface{item},
					Integrations:  []Integration{},
					Handlers:      []Handler{},
					Relationships: []Relationship{},
				}),
				testEvidence{"ev_cli": true, "ev_access": true},
				references,
			)
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("expected %s rejection, got %v", test.name, err)
			}
		})
	}
}

func TestValidateResultRejectsPositiveAccessWithoutEvidence(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	item.Access = &Access{
		Authentication: "not_required",
		RoleIDs:        []string{},
		PermissionIDs:  []string{},
		Confidence:     0.9,
		EvidenceIDs:    []string{},
	}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_cli": true},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing access evidence error, got %v", err)
	}
}

func TestValidateResultRejectsHandlerForUndeclaredInterface(t *testing.T) {
	handler := validHandler("cli.missing")

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{},
			Handlers:      []Handler{handler},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_handler": true},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown interface") {
		t.Fatalf("expected unknown handler interface error, got %v", err)
	}
}

func TestValidateResultRejectsHandlerReferencingIntegration(t *testing.T) {
	integration := validHTTPIntegration()
	handler := validHandler(integration.ID)

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{handler},
			Relationships: []Relationship{},
		}),
		testEvidence{
			"ev_integration": true,
			"ev_handler":     true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown interface") {
		t.Fatalf("expected integration to be invalid as a handler interface, got %v", err)
	}
}

func TestValidateResultRejectsHandlerWithoutEvidence(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	handler := validHandler(item.ID)
	handler.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{handler},
			Relationships: []Relationship{},
		}),
		testEvidence{"ev_cli": true},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing handler evidence error, got %v", err)
	}
}

func TestValidateResultRejectsRelationshipForUndeclaredInterface(t *testing.T) {
	item := validCLIInterface("cli.root", "noescope")
	relationship := validRelationship(item.ID, "cli.missing")

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{relationship},
		}),
		testEvidence{
			"ev_cli":          true,
			"ev_relationship": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown to interface") {
		t.Fatalf("expected unknown relationship interface error, got %v", err)
	}
}

func TestValidateResultRejectsRelationshipWithoutEvidence(t *testing.T) {
	root := validCLIInterface("cli.root", "noescope")
	discover := validCLIInterface("cli.discover", "noescope discover")
	relationship := validRelationship(root.ID, discover.ID)
	relationship.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{root, discover},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{relationship},
		}),
		testEvidence{"ev_cli": true},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing relationship evidence error, got %v", err)
	}
}

func TestValidateResultRejectsIntegrationCallWithUnknownInterface(t *testing.T) {
	integration := validHTTPIntegration()
	relationship := validIntegrationCall("cli.missing", integration.ID)

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{relationship},
		}),
		testEvidence{
			"ev_integration":  true,
			"ev_relationship": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown from interface") {
		t.Fatalf("expected unknown integration-call interface error, got %v", err)
	}
}

func TestValidateResultRejectsIntegrationCallWithUnknownIntegration(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	relationship := validIntegrationCall(item.ID, "integration.missing")

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{},
			Handlers:      []Handler{},
			Relationships: []Relationship{relationship},
		}),
		testEvidence{
			"ev_cli":          true,
			"ev_relationship": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown integration") {
		t.Fatalf("expected unknown integration-call target error, got %v", err)
	}
}

func TestValidateResultRejectsIntegrationCallWithoutEvidence(t *testing.T) {
	item := validCLIInterface("cli.discover", "noescope discover")
	integration := validHTTPIntegration()
	relationship := validIntegrationCall(item.ID, integration.ID)
	relationship.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{
			Interfaces:    []Interface{item},
			Integrations:  []Integration{integration},
			Handlers:      []Handler{},
			Relationships: []Relationship{relationship},
		}),
		testEvidence{
			"ev_cli":         true,
			"ev_integration": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing integration-call evidence error, got %v", err)
	}
}

func TestTaskDistinguishesSurfacesFromFeatures(t *testing.T) {
	prompt := Task().Objective + "\n" + Task().Instructions

	for _, expected := range []string{
		"This is not Feature Discovery",
		"Do not group routes or commands into business features",
		"Ordinary helpers, repository methods",
		"intentionally reachable or invokable",
		"APPLICATION INTERFACE",
		"EXTERNAL INTEGRATION",
		"POST /api/customers exposed by the target is an interface",
		"POST https://api.stripe.com made by the target is an integration",
		"OpenAI-compatible chat completions service called by Noescope is an integration",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("surface prompt does not contain %q", expected)
		}
	}
}

func TestTaskAdaptsToCLIApplications(t *testing.T) {
	prompt := Task().Objective + "\n" + Task().Instructions

	for _, expected := range []string{
		"For CLI applications",
		"Cobra, urfave, or flag command tree",
		"noescope discover",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("surface prompt does not contain %q", expected)
		}
	}
}

func TestSurfacePromptContainsAllPriorFindingsWithoutChatHistory(t *testing.T) {
	requests := make(chan llm.ChatRequest, 1)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request llm.ChatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			requests <- request
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(llm.ChatResponse{
				Choices: []llm.Choice{
					{
						Message: llm.Message{
							Role:    "assistant",
							Content: `{"status":"completed","summary":"No surface found.","findings":{"interfaces":[],"integrations":[],"handlers":[],"relationships":[]}}`,
						},
					},
				},
			})
		}),
	)
	defer server.Close()

	runner := investigation.NewRunner(
		llm.NewClient(server.URL, "", "test-model"),
		tools.NewRegistry(),
		evidence.NewStore(t.TempDir()),
	)

	priorFindings := json.RawMessage(`{
      "architecture": {"languages": [{"name": "Go"}]},
      "authentication": {"authentication_present": false},
      "authorization": {"authorization_present": false},
      "entities": {"entities": [{"id": "assessment"}]}
    }`)

	task := Task()
	task.Context = priorFindings
	task.ValidateResult = nil
	task.Budget.MaxTurns = 1
	task.Budget.FinalizeTurns = 1
	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	request := <-requests
	if len(request.Messages) != 3 {
		t.Fatalf(
			"expected fresh system, objective, and finalization messages, got %d",
			len(request.Messages),
		)
	}

	systemPrompt := request.Messages[0].Content
	for _, expected := range []string{
		`"architecture"`,
		`"authentication"`,
		`"authorization"`,
		`"entities"`,
		`"id": "assessment"`,
	} {
		if !strings.Contains(systemPrompt, expected) {
			t.Fatalf("surface system prompt does not contain %q", expected)
		}
	}

	if request.Messages[1].Content != Task().Objective {
		t.Fatal("the only user message should be the surface objective")
	}
}

func TestSchemaRepresentsNoescopeCLICommandsAndLLMIntegration(t *testing.T) {
	commands := []struct {
		id      string
		command string
	}{
		{id: "cli.root", command: "noescope"},
		{id: "cli.version", command: "noescope version"},
		{id: "cli.init", command: "noescope init"},
		{id: "cli.discover", command: "noescope discover"},
	}

	findings := Findings{
		Interfaces:   make([]Interface, 0, len(commands)),
		Integrations: []Integration{validHTTPIntegration()},
		Handlers:     []Handler{},
		Relationships: []Relationship{
			validIntegrationCall("cli.discover", "integration.llm"),
		},
	}
	for _, command := range commands {
		findings.Interfaces = append(
			findings.Interfaces,
			validCLIInterface(command.id, command.command),
		)
	}

	if err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{
			"ev_cli":          true,
			"ev_integration":  true,
			"ev_relationship": true,
		},
	); err != nil {
		t.Fatalf("expected Noescope surface model to be representable, got %v", err)
	}
}

func validCLIInterface(id, command string) Interface {
	return Interface{
		ID:          id,
		Type:        "cli_command",
		Name:        command,
		Description: "An externally invokable CLI command.",
		Locator: InterfaceLocator{
			Command: command,
		},
		EntityIDs: []string{},
		SourceComponents: []SourceComponent{
			{
				Path:   "cmd/noescope/main.go",
				Symbol: "discoverCommand",
			},
		},
		Confidence:  0.95,
		EvidenceIDs: []string{"ev_cli"},
	}
}

func validHandler(interfaceID string) Handler {
	return Handler{
		ID:           "handler.cli.discover",
		Type:         "command_handler",
		Name:         "discoverCommand callback",
		Path:         "cmd/noescope/main.go",
		Symbol:       "discoverCommand",
		InterfaceIDs: []string{interfaceID},
		Confidence:   0.95,
		EvidenceIDs:  []string{"ev_handler"},
	}
}

func validHTTPIntegration() Integration {
	return Integration{
		ID:          "integration.llm",
		Type:        "http_api",
		Name:        "OpenAI-compatible LLM API",
		Description: "Provides chat completions used by repository investigations.",
		Locator: IntegrationLocator{
			BaseURL: "configurable",
			Path:    "/chat/completions",
			Method:  "POST",
		},
		Authentication: IntegrationAuthentication{
			Type:             "bearer",
			CredentialSource: "ai.api_key",
		},
		EntityIDs: []string{},
		SourceComponents: []SourceComponent{
			{
				Path:   "internal/llm/client.go",
				Symbol: "Client.Chat",
			},
		},
		Confidence:  0.95,
		EvidenceIDs: []string{"ev_integration"},
	}
}

func validRelationship(fromID, toID string) Relationship {
	return Relationship{
		Type:            "command_flow",
		FromInterfaceID: fromID,
		ToInterfaceID:   toID,
		Description:     "The root command exposes the discover subcommand.",
		Confidence:      0.9,
		EvidenceIDs:     []string{"ev_relationship"},
	}
}

func validIntegrationCall(fromID, toID string) Relationship {
	return Relationship{
		Type:            "integration_call",
		FromInterfaceID: fromID,
		ToIntegrationID: toID,
		Description:     "The discover command calls the configured LLM service.",
		Confidence:      0.95,
		EvidenceIDs:     []string{"ev_relationship"},
	}
}

func resultWithFindings(
	t *testing.T,
	findings Findings,
) *investigation.Result {
	t.Helper()

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}

	return &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: data,
	}
}

func resultWithRawFindings(findings json.RawMessage) *investigation.Result {
	return &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: findings,
	}
}
