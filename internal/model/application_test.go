package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

func TestBuildAssemblesCompleteCanonicalApplication(t *testing.T) {
	input := completeBuildInput()
	application, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}

	if application.SchemaVersion != "0.1" {
		t.Fatalf("unexpected schema version %q", application.SchemaVersion)
	}
	if application.Metadata.ProjectName != "kanboard" ||
		application.Metadata.RunID != "run_test" ||
		application.Metadata.Source.GitCommit != "9ce6a5e" {
		t.Fatalf("metadata not preserved: %#v", application.Metadata)
	}
	if application.Metadata.ApplicationURL != "https://kanboard.example/app" {
		t.Fatalf("application URL was not safely normalized: %q", application.Metadata.ApplicationURL)
	}
	if application.Architecture.ArchitectureStyle.Value != "custom MVC" ||
		application.Architecture.Languages[0].Name != "PHP" {
		t.Fatalf("architecture not preserved: %#v", application.Architecture)
	}
	if !application.Identity.Authentication.AuthenticationPresent ||
		!application.Identity.Authorization.AuthorizationPresent {
		t.Fatalf("identity findings not nested correctly: %#v", application.Identity)
	}
	if len(application.Entities) != 1 || application.Entities[0].ID != "project" {
		t.Fatalf("entities not preserved: %#v", application.Entities)
	}
	if len(application.Surface.Interfaces) != 1 ||
		len(application.Surface.Integrations) != 1 ||
		application.Surface.Interfaces[0].ID == application.Surface.Integrations[0].ID {
		t.Fatalf("surface separation not preserved: %#v", application.Surface)
	}
	if len(application.Features) != 1 ||
		application.Features[0].Children[0].ID != "projects.create" {
		t.Fatalf("feature hierarchy not preserved: %#v", application.Features)
	}
	if application.Features[0].EvidenceIDs[0] != "ev_feature" ||
		application.Entities[0].EvidenceIDs[0] != "ev_entity" {
		t.Fatal("canonical evidence IDs were not preserved")
	}
	if application.Discovery.Stages.Features.Status != "completed" ||
		application.Discovery.Stages.Architecture.Unresolved[0].Question != "Which proxy is deployed?" {
		t.Fatalf("stage provenance not preserved: %#v", application.Discovery)
	}
	if application.Discovery.EvidenceFile != "../evidence.jsonl" {
		t.Fatalf("unexpected evidence reference %q", application.Discovery.EvidenceFile)
	}
}

func TestBuildExcludesSummariesAndSecrets(t *testing.T) {
	application, err := Build(completeBuildInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(application)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{
		"summary-secret-value",
		"api-key-secret-value",
		"user:password",
		"token=secret",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("canonical application contains forbidden value %q", forbidden)
		}
	}
	if strings.Contains(text, `"summary"`) {
		t.Fatal("canonical application contains Result.Summary fields")
	}
}

func TestBuildOrderingIsDeterministicWithoutReorderingFeatureTree(t *testing.T) {
	input := completeBuildInput()
	input.Findings.Architecture.Languages = append(
		input.Findings.Architecture.Languages,
		architecture.Technology{Name: "JavaScript"},
	)
	input.Findings.Features.Features = append(
		input.Findings.Features.Features,
		features.Node{ID: "administration", Name: "Administration", Type: "module"},
	)
	first, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("application assembly is not deterministic")
	}
	if first.Architecture.Languages[0].Name != "JavaScript" ||
		first.Architecture.Languages[1].Name != "PHP" {
		t.Fatal("unordered architecture sets were not normalized")
	}
	if first.Features[0].ID != "projects" || first.Features[1].ID != "administration" {
		t.Fatal("meaningful Feature-tree order was changed")
	}
	if input.Findings.Architecture.Languages[0].Name != "PHP" {
		t.Fatal("assembly mutated original canonical findings")
	}
}

func TestBuildRequiresAllSixCanonicalFindingSets(t *testing.T) {
	input := completeBuildInput()
	input.Findings.Surface = nil

	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "missing findings: [surface]") {
		t.Fatalf("expected incomplete model error, got %v", err)
	}
}

func completeBuildInput() BuildInput {
	architectureFindings := &architecture.Findings{
		Languages: []architecture.Technology{{
			Name: "PHP", Confidence: 1, EvidenceIDs: []string{"ev_arch"},
		}},
		ArchitectureStyle: architecture.Statement{
			Value: "custom MVC", Confidence: 0.9, EvidenceIDs: []string{"ev_arch"},
		},
		Entrypoints: []architecture.Entrypoint{{
			Path: "index.php", Type: "web", Purpose: "Web entrypoint",
			Confidence: 0.9, EvidenceIDs: []string{"ev_arch"},
		}},
	}
	authenticationFindings := &authentication.Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_authn"},
		Mechanisms: []authentication.Mechanism{{
			ID: "web-session", Type: "form_session",
			CredentialFields: []string{"username", "password"},
			Confidence:       0.9, EvidenceIDs: []string{"ev_authn"},
		}},
	}
	authorizationFindings := &authorization.Findings{
		AuthorizationPresent: true,
		Confidence:           0.9,
		EvidenceIDs:          []string{"ev_authz"},
		Model: &authorization.Model{
			Type: "rbac", Description: "Role-based access.",
			Confidence: 0.9, EvidenceIDs: []string{"ev_authz"},
		},
		Roles:       []authorization.Role{{ID: "admin", Name: "Administrator"}},
		Permissions: []authorization.Permission{{ID: "project.create", Name: "Create Project"}},
	}
	entityFindings := &entities.Findings{Entities: []entities.Entity{{
		ID: "project", Name: "Project", Description: "A managed project.",
		Confidence: 0.9, EvidenceIDs: []string{"ev_entity"},
	}}}
	surfaceFindings := &surface.Findings{
		Interfaces: []surface.Interface{{
			ID: "project.create", Type: "form_action", Name: "Create Project",
			Description: "Creates a project.",
			Locator:     surface.InterfaceLocator{Method: "POST", Path: "/projects"},
			Access: &surface.Access{
				Authentication: "required", PermissionIDs: []string{"project.create"},
			},
			EntityIDs: []string{"project"}, Confidence: 0.9,
			EvidenceIDs: []string{"ev_surface"},
		}},
		Integrations: []surface.Integration{{
			ID: "integration.smtp", Type: "email", Name: "SMTP",
			Description:    "Email delivery.",
			Locator:        surface.IntegrationLocator{Name: "configured SMTP server"},
			Authentication: surface.IntegrationAuthentication{Type: "unknown"},
			Confidence:     0.9, EvidenceIDs: []string{"ev_integration"},
		}},
	}
	featureFindings := &features.Findings{Features: []features.Node{{
		ID: "projects", Name: "Projects", Type: "module",
		Description: "Project functionality.",
		Access:      features.Access{Authentication: "required"},
		EntityIDs:   []string{"project"},
		Children: []features.Node{{
			ID: "projects.create", Name: "Create Project", Type: "action",
			Description: "Creates a project.",
			Access: features.Access{
				Authentication: "required", PermissionIDs: []string{"project.create"},
			},
			EntityIDs: []string{"project"}, InterfaceIDs: []string{"project.create"},
			Confidence: 0.9, EvidenceIDs: []string{"ev_feature"},
		}},
		Confidence: 0.9, EvidenceIDs: []string{"ev_feature"},
	}}}

	result := func(unresolved ...investigation.UnresolvedQuestion) *investigation.Result {
		return &investigation.Result{
			Status: "completed", Summary: "summary-secret-value api-key-secret-value",
			Unresolved: unresolved,
		}
	}
	return BuildInput{
		Metadata: Metadata{
			ProjectName: "kanboard",
			GeneratedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
			RunID:       "run_test",
			Source: SourceMetadata{
				Root: "/src/kanboard", GitBranch: "main", GitCommit: "9ce6a5e",
			},
			ApplicationURL: "https://user:password@kanboard.example/app?token=secret#fragment",
		},
		Findings: Findings{
			Architecture: architectureFindings, Authentication: authenticationFindings,
			Authorization: authorizationFindings, Entities: entityFindings,
			Surface: surfaceFindings, Features: featureFindings,
		},
		Results: Results{
			Architecture: result(investigation.UnresolvedQuestion{
				Question: "Which proxy is deployed?", Priority: "low", Reason: "Not in source.",
			}),
			Authentication: result(), Authorization: result(), Entities: result(),
			Surface: result(), Features: result(),
		},
	}
}
