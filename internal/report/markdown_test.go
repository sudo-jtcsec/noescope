package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

func TestMarkdownRendersCanonicalApplicationDeterministically(t *testing.T) {
	application := reportFixture()
	first, err := Markdown(application)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Markdown(application)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Markdown output is not deterministic")
	}

	text := string(first)
	for _, want := range []string{
		"# Kanboard",
		"## Application Inventory",
		"- Domain entities: 1",
		"- Application interfaces: 1",
		"- External integrations: 1",
		"- Functional modules: 2",
		"- Functional nodes: 4",
		"## Authentication",
		"### form_session (`web-session`)",
		"## Authorization",
		"`project.create` — Create Project",
		"## Domain Model",
		"### Project",
		"## Application Interfaces",
		"### Discovery Coverage",
		"- Web: completed; applicable=Yes; interfaces=1; integrations=0",
		"#### Create Project",
		"## External Integrations",
		"### SMTP",
		"### Projects",
		"#### Project Management",
		"##### Create Project",
		"### Background Processing",
		"- Access: Authentication required",
		"- Permissions: `project.create`",
		"- Entities: `project`",
		"- Interfaces: `project.create`",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Markdown missing %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "## Application Interfaces") > strings.Index(text, "## External Integrations") {
		t.Fatal("interfaces and integrations were not rendered as separate ordered sections")
	}
	for _, forbidden := range []string{"summary-secret", "api-key-secret"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Markdown contains forbidden value %q", forbidden)
		}
	}
}

func TestMarkdownRejectsExcessiveFeatureDepth(t *testing.T) {
	application := reportFixture()
	node := features.Node{ID: "root", Name: "Root", Type: "module"}
	cursor := &node
	for depth := 0; depth < maxFeatureRenderDepth; depth++ {
		cursor.Children = []features.Node{{
			ID: cursor.ID + ".child", Name: "Child", Type: "feature",
		}}
		cursor = &cursor.Children[0]
	}
	application.Features = []features.Node{node}

	_, err := Markdown(application)
	if err == nil || !strings.Contains(err.Error(), "maximum render depth") {
		t.Fatalf("expected bounded recursion error, got %v", err)
	}
}

func reportFixture() *model.Application {
	return &model.Application{
		SchemaVersion: model.SchemaVersion,
		Metadata: model.Metadata{
			ProjectName: "Kanboard", RunID: "run_test",
			GeneratedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
			Source: model.SourceMetadata{
				GitBranch: "main", GitCommit: "9ce6a5e",
			},
		},
		Architecture: architecture.Findings{
			Languages:         []architecture.Technology{{Name: "PHP"}},
			ArchitectureStyle: architecture.Statement{Value: "custom MVC"},
			Entrypoints: []architecture.Entrypoint{{
				Path: "index.php", Type: "web", Purpose: "Web entrypoint",
			}},
		},
		Identity: model.Identity{
			Authentication: authentication.Findings{
				AuthenticationPresent: true, Confidence: 0.95,
				Mechanisms: []authentication.Mechanism{{
					ID: "web-session", Type: "form_session",
					LoginEntrypoints: []string{"/login"},
					Session:          &authentication.Session{Type: "cookie", Name: "session"},
				}},
			},
			Authorization: authorization.Findings{
				AuthorizationPresent: true, Confidence: 0.9,
				Model:       &authorization.Model{Type: "rbac", Description: "Role-based access."},
				Roles:       []authorization.Role{{ID: "admin", Name: "Administrator"}},
				Permissions: []authorization.Permission{{ID: "project.create", Name: "Create Project"}},
				Enforcement: []authorization.Enforcement{{
					Name: "authorize", Type: "controller", Path: "app/Controller/BaseController.php",
				}},
			},
		},
		Entities: []entities.Entity{{
			ID: "project", Name: "Project", Description: "A managed project.",
			Persistence: []entities.Persistence{{Type: "database_table", Name: "projects"}},
		}},
		Surface: surface.Findings{
			Coverage: surface.Coverage{
				Web: surface.CategoryCoverage{
					Applicable: true, Status: "completed", Interfaces: 1,
				},
				API:          surface.CategoryCoverage{Status: "skipped"},
				CLI:          surface.CategoryCoverage{Status: "skipped"},
				Background:   surface.CategoryCoverage{Status: "skipped"},
				Integrations: surface.CategoryCoverage{Applicable: true, Status: "completed", Integrations: 1},
			},
			Interfaces: []surface.Interface{{
				ID: "project.create", Type: "form_action", Name: "Create Project",
				Description: "Creates a project.",
				Locator:     surface.InterfaceLocator{Method: "POST", Path: "/projects"},
				Access: &surface.Access{
					Authentication: "required", PermissionIDs: []string{"project.create"},
				},
				EntityIDs: []string{"project"},
			}},
			Integrations: []surface.Integration{{
				ID: "integration.smtp", Type: "email", Name: "SMTP",
				Description:    "Sends application email.",
				Locator:        surface.IntegrationLocator{Name: "configured SMTP server"},
				Authentication: surface.IntegrationAuthentication{Type: "unknown"},
			}},
		},
		Features: []features.Node{
			{
				ID: "projects", Name: "Projects", Type: "module",
				Description: "Project functionality.",
				Access:      features.Access{Authentication: "required"},
				EntityIDs:   []string{"project"},
				Children: []features.Node{{
					ID: "projects.manage", Name: "Project Management", Type: "feature",
					Description: "Manage projects.",
					Access:      features.Access{Authentication: "required"},
					Children: []features.Node{{
						ID: "projects.manage.create", Name: "Create Project", Type: "action",
						Description: "Creates a project.",
						Access: features.Access{
							Authentication: "required", PermissionIDs: []string{"project.create"},
						},
						EntityIDs: []string{"project"}, InterfaceIDs: []string{"project.create"},
					}},
				}},
			},
			{
				ID: "background", Name: "Background Processing", Type: "module",
				Description: "Processes queued work.",
				Access:      features.Access{Authentication: "not_required"},
			},
		},
	}
}
