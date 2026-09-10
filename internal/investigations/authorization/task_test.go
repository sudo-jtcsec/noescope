package authorization

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

func TestValidateResultAcceptsNoAuthorization(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthorizationPresent: false,
		Confidence:           0.98,
		EvidenceIDs:          []string{"ev_authorization_search"},
		Roles:                []Role{},
		Permissions:          []Permission{},
		RolePermissions:      []RolePermission{},
		Enforcement:          []Enforcement{},
	})

	if err := validateResult(
		result,
		testEvidence{"ev_authorization_search": true},
	); err != nil {
		t.Fatalf("expected no-authorization result to be valid, got %v", err)
	}
}

func TestValidateResultRejectsNoAuthorizationWithoutEvidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthorizationPresent: false,
		Confidence:           0.98,
		EvidenceIDs:          []string{},
		Roles:                []Role{},
		Permissions:          []Permission{},
		RolePermissions:      []RolePermission{},
		Enforcement:          []Enforcement{},
	})

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing conclusion evidence error, got %v", err)
	}
}

func TestValidateResultRejectsUnknownConclusionEvidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthorizationPresent: false,
		Confidence:           0.98,
		EvidenceIDs:          []string{"ev_unknown"},
		Roles:                []Role{},
		Permissions:          []Permission{},
		RolePermissions:      []RolePermission{},
		Enforcement:          []Enforcement{},
	})

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("expected unknown conclusion evidence error, got %v", err)
	}
}

func TestValidateResultRejectsInvalidConclusionConfidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthorizationPresent: false,
		Confidence:           -0.1,
		EvidenceIDs:          []string{"ev_authorization_search"},
		Roles:                []Role{},
		Permissions:          []Permission{},
		RolePermissions:      []RolePermission{},
		Enforcement:          []Enforcement{},
	})

	err := validateResult(
		result,
		testEvidence{"ev_authorization_search": true},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid confidence") {
		t.Fatalf("expected conclusion confidence error, got %v", err)
	}
}

func TestValidateResultAcceptsSupportedAuthorization(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthorizationPresent: true,
		Confidence:           0.9,
		EvidenceIDs:          []string{"ev_model"},
		Model: &Model{
			Type:        "rbac",
			Description: "Roles grant named permissions.",
			Confidence:  0.9,
			EvidenceIDs: []string{"ev_model"},
		},
		Roles: []Role{
			{
				ID:          "admin",
				Name:        "Administrator",
				Inherits:    []string{},
				Confidence:  0.9,
				EvidenceIDs: []string{"ev_role"},
			},
		},
		Permissions: []Permission{
			{
				ID:          "assessment.run",
				Name:        "Run assessments",
				Confidence:  0.9,
				EvidenceIDs: []string{"ev_permission"},
			},
		},
		RolePermissions: []RolePermission{
			{
				RoleID:        "admin",
				PermissionIDs: []string{"assessment.run"},
				Confidence:    0.9,
				EvidenceIDs:   []string{"ev_mapping"},
			},
		},
		Enforcement: []Enforcement{
			{
				Type:        "middleware",
				Name:        "requirePermission",
				Description: "Checks the named permission.",
				Confidence:  0.9,
				EvidenceIDs: []string{"ev_enforcement"},
			},
		},
	})

	evidence := testEvidence{
		"ev_model":       true,
		"ev_role":        true,
		"ev_permission":  true,
		"ev_mapping":     true,
		"ev_enforcement": true,
	}

	if err := validateResult(result, evidence); err != nil {
		t.Fatalf("expected supported authorization result to be valid, got %v", err)
	}
}

func TestValidateResultRejectsModelWithoutEvidence(t *testing.T) {
	findings := authorizationFindings()
	findings.Model = &Model{
		Type:       "rbac",
		Confidence: 0.9,
	}

	err := validateResult(resultWithFindings(t, findings), testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing model evidence error, got %v", err)
	}
}

func TestValidateResultRejectsRoleWithoutEvidence(t *testing.T) {
	findings := authorizationFindings()
	findings.Roles = []Role{
		{
			ID:         "admin",
			Confidence: 0.9,
		},
	}

	err := validateResult(resultWithFindings(t, findings), testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing role evidence error, got %v", err)
	}
}

func TestValidateResultRejectsPermissionWithUnknownEvidence(t *testing.T) {
	findings := authorizationFindings()
	findings.Permissions = []Permission{
		{
			ID:          "assessment.run",
			Confidence:  0.9,
			EvidenceIDs: []string{"ev_unknown"},
		},
	}

	err := validateResult(resultWithFindings(t, findings), testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("expected unknown permission evidence error, got %v", err)
	}
}

func TestValidateResultRejectsRolePermissionWithoutEvidence(t *testing.T) {
	findings := authorizationFindings()
	findings.Roles = []Role{{ID: "admin"}}
	findings.Permissions = []Permission{{ID: "assessment.run"}}
	findings.RolePermissions = []RolePermission{
		{
			RoleID:        "admin",
			PermissionIDs: []string{"assessment.run"},
			Confidence:    0.9,
		},
	}

	err := validateResult(resultWithFindings(t, findings), testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing mapping evidence error, got %v", err)
	}
}

func TestValidateResultRejectsEnforcementWithoutEvidence(t *testing.T) {
	findings := authorizationFindings()
	findings.Enforcement = []Enforcement{
		{
			Type:       "middleware",
			Name:       "requireAdmin",
			Confidence: 0.9,
		},
	}

	err := validateResult(resultWithFindings(t, findings), testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing enforcement evidence error, got %v", err)
	}
}

func TestAuthorizationPromptIncludesBothPriorFindingsWithoutChatHistory(
	t *testing.T,
) {
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
							Role: "assistant",
							ToolCalls: []llm.ToolCall{
								{
									ID:   "call_submit",
									Type: "function",
									Function: llm.FunctionCall{
										Name:      "submit_investigation_result",
										Arguments: `{"status":"completed","summary":"No authorization found.","findings":{"authorization_present":false,"confidence":0.9,"evidence_ids":["ev_search"],"roles":[],"permissions":[],"role_permissions":[],"enforcement":[]}}`,
									},
								},
							},
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
      "architecture": {
        "languages": [{"name": "Go"}],
        "entrypoints": [{"path": "cmd/noescope/main.go"}]
      },
      "authentication": {
        "authentication_present": false,
        "confidence": 0.98,
        "evidence_ids": ["ev_auth_search"],
        "mechanisms": []
      }
    }`)

	task := Task()
	task.Context = append(json.RawMessage(nil), priorFindings...)
	task.ValidateResult = nil

	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	request := <-requests
	if len(request.Messages) != 2 {
		t.Fatalf(
			"expected fresh system and objective messages only, got %d",
			len(request.Messages),
		)
	}

	systemPrompt := request.Messages[0].Content
	for _, expected := range []string{
		`"architecture"`,
		`"authentication"`,
		`"cmd/noescope/main.go"`,
		`"authentication_present": false`,
	} {
		if !strings.Contains(systemPrompt, expected) {
			t.Fatalf("system prompt does not contain %q", expected)
		}
	}

	if request.Messages[1].Content != Task().Objective {
		t.Fatal("the only user message should be the authorization objective")
	}
}

func TestTaskDoesNotClassifyServiceAPIKeysAsUserAuthorization(t *testing.T) {
	task := Task()
	prompt := task.Objective + "\n" + task.Instructions

	if !strings.Contains(
		prompt,
		"using an API key to authenticate an outbound LLM or service request",
	) {
		t.Fatal("task does not distinguish service API keys from user authorization")
	}
}

func authorizationFindings() Findings {
	return Findings{
		AuthorizationPresent: true,
		Confidence:           0,
		EvidenceIDs:          []string{},
		Model: &Model{
			Type: "unknown",
		},
		Roles:           []Role{},
		Permissions:     []Permission{},
		RolePermissions: []RolePermission{},
		Enforcement:     []Enforcement{},
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
