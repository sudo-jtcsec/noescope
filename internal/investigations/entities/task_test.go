package entities

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

type testEvidence map[string]bool

func (e testEvidence) Exists(id string) bool {
	return e[id]
}

func TestValidateResultRejectsStringifiedEntityFindings(t *testing.T) {
	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: json.RawMessage(`"{\"entities\":[]}"`),
	}

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"entity findings: expected object, got string",
	) {
		t.Fatalf("expected useful stringified findings error, got %v", err)
	}
}

func TestValidateResultAcceptsEmptyEntityList(t *testing.T) {
	result := resultWithFindings(t, Findings{Entities: []Entity{}})

	if err := validateResult(result, testEvidence{}); err != nil {
		t.Fatalf("expected empty entity list to be valid, got %v", err)
	}
}

func TestValidateResultRejectsEntityWithoutEvidence(t *testing.T) {
	entity := validEntity()
	entity.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing entity evidence error, got %v", err)
	}
}

func TestValidateResultRejectsZeroConfidenceEntity(t *testing.T) {
	entity := validEntity()
	entity.Confidence = 0
	entity.EvidenceIDs = []string{}

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{},
	)
	if err == nil || !strings.Contains(err.Error(), "zero confidence") {
		t.Fatalf("expected unsupported entity error, got %v", err)
	}
}

func TestValidateResultRejectsUnknownEntityEvidence(t *testing.T) {
	entity := validEntity()
	entity.EvidenceIDs = []string{"ev_unknown"}

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("expected unknown entity evidence error, got %v", err)
	}
}

func TestValidateResultAcceptsEvidenceBackedEntity(t *testing.T) {
	entity := validEntity()

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{"ev_assessment": true},
	)
	if err != nil {
		t.Fatalf("expected evidence-backed entity to be valid, got %v", err)
	}
}

func TestValidateResultRejectsPersistenceWithoutEvidence(t *testing.T) {
	entity := validEntity()
	entity.Persistence = []Persistence{
		{
			Type:       "database_table",
			Name:       "assessments",
			Confidence: 0.9,
		},
	}

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{"ev_assessment": true},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing persistence evidence error, got %v", err)
	}
}

func TestValidateResultRejectsRelationshipWithoutEvidence(t *testing.T) {
	assessment := validEntity()
	assessment.Relationships = []Relationship{
		{
			Type:           "belongs_to",
			TargetEntityID: "customer",
			Description:    "Assessment belongs to a customer.",
			Confidence:     0.9,
		},
	}
	customer := Entity{
		ID:               "customer",
		Name:             "Customer",
		Description:      "Represents the customer receiving an assessment.",
		Aliases:          []string{},
		SourceComponents: []SourceComponent{},
		Persistence:      []Persistence{},
		Relationships:    []Relationship{},
		Confidence:       0.9,
		EvidenceIDs:      []string{"ev_customer"},
	}

	err := validateResult(
		resultWithFindings(t, Findings{
			Entities: []Entity{assessment, customer},
		}),
		testEvidence{
			"ev_assessment": true,
			"ev_customer":   true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing relationship evidence error, got %v", err)
	}
}

func TestValidateResultRejectsUndeclaredRelationshipTarget(t *testing.T) {
	entity := validEntity()
	entity.Relationships = []Relationship{
		{
			Type:           "belongs_to",
			TargetEntityID: "customer",
			Description:    "Assessment belongs to a customer.",
			Confidence:     0.9,
			EvidenceIDs:    []string{"ev_relationship"},
		},
	}

	err := validateResult(
		resultWithFindings(t, Findings{Entities: []Entity{entity}}),
		testEvidence{
			"ev_assessment":   true,
			"ev_relationship": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "undeclared entity") {
		t.Fatalf("expected undeclared relationship target error, got %v", err)
	}
}

func TestEntityPromptIncludesAllPriorFindingsWithoutChatHistory(t *testing.T) {
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
							Content: `{"status":"completed","summary":"No major domain entities found.","findings":{"entities":[]}}`,
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
      "authorization": {"authorization_present": false}
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
		`"name": "Go"`,
	} {
		if !strings.Contains(systemPrompt, expected) {
			t.Fatalf("entity system prompt does not contain %q", expected)
		}
	}

	if request.Messages[1].Content != Task().Objective {
		t.Fatal("the only user message should be the entity objective")
	}
}

func TestTaskDistinguishesDomainEntitiesFromImplementationTypes(t *testing.T) {
	task := Task()
	prompt := task.Objective + "\n" + task.Instructions

	for _, expected := range []string{
		"Do not mechanically classify every struct, class, table, or source noun as an entity",
		"implementation concepts rather than domain entities",
		"Multiple artifacts",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("entity task prompt does not contain %q", expected)
		}
	}
}

func validEntity() Entity {
	return Entity{
		ID:          "assessment",
		Name:        "Assessment",
		Description: "Represents an assessment performed against a target.",
		Aliases:     []string{"scan"},
		SourceComponents: []SourceComponent{
			{
				Path:   "internal/assessment/assessment.go",
				Symbol: "Assessment",
			},
		},
		Persistence:   []Persistence{},
		Relationships: []Relationship{},
		Confidence:    0.95,
		EvidenceIDs:   []string{"ev_assessment"},
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
