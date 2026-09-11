package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	"github.com/sudo-jtcsec/noescope/internal/model"
)

func TestApplicationArtifactsAreWrittenForCompletePipeline(t *testing.T) {
	runRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(runRoot, "output"), 0755); err != nil {
		t.Fatal(err)
	}
	findings, results := artifactFixture()
	applicationPath, markdownPath, written, err := writeApplicationArtifactsForStage(
		StageFeatures,
		runRoot,
		model.Metadata{
			ProjectName: "fixture", RunID: "run_fixture",
			GeneratedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
			Source:      model.SourceMetadata{GitCommit: "abc123"},
		},
		findings,
		results,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !written {
		t.Fatal("complete pipeline did not write application artifacts")
	}
	if applicationPath != filepath.Join(runRoot, "output", "application.json") ||
		markdownPath != filepath.Join(runRoot, "output", "application.md") {
		t.Fatalf("unexpected artifact paths %q and %q", applicationPath, markdownPath)
	}
	raw, err := os.ReadFile(applicationPath)
	if err != nil {
		t.Fatal(err)
	}
	var application model.Application
	if err := json.Unmarshal(raw, &application); err != nil {
		t.Fatal(err)
	}
	if application.SchemaVersion != model.SchemaVersion ||
		application.Metadata.RunID != "run_fixture" {
		t.Fatalf("unexpected application model: %#v", application)
	}
	if strings.Contains(string(raw), "summary-must-not-be-canonical") ||
		strings.Contains(string(raw), "api-key-secret-value") {
		t.Fatal("stage Summary leaked into application.json")
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "# fixture") ||
		strings.Contains(string(markdown), "summary-must-not-be-canonical") ||
		strings.Contains(string(markdown), "api-key-secret-value") {
		t.Fatalf("unexpected application Markdown:\n%s", markdown)
	}
}

func TestPartialPipelineDoesNotWriteCompleteApplicationArtifacts(t *testing.T) {
	for _, stage := range []Stage{
		StageArchitecture,
		StageAuthentication,
		StageAuthorization,
		StageEntities,
		StageSurface,
	} {
		t.Run(string(stage), func(t *testing.T) {
			runRoot := t.TempDir()
			applicationPath, markdownPath, written, err := writeApplicationArtifactsForStage(
				stage,
				runRoot,
				model.Metadata{},
				completedFindings{},
				completedResults{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if written || applicationPath != "" || markdownPath != "" {
				t.Fatalf("partial stage %q emitted complete artifacts", stage)
			}
			for _, name := range []string{"application.json", "application.md"} {
				_, err := os.Stat(filepath.Join(runRoot, "output", name))
				if !os.IsNotExist(err) {
					t.Fatalf("partial stage %q created %s", stage, name)
				}
			}
		})
	}
}

func artifactFixture() (completedFindings, completedResults) {
	findings := completedFindings{
		architecture: &architecture.Findings{
			Languages: []architecture.Technology{}, Formats: []architecture.Technology{},
			Frameworks: []architecture.Technology{}, Libraries: []architecture.Technology{},
			Databases: []architecture.Technology{}, WebServers: []architecture.Technology{},
			ExternalInterfaces: []architecture.Technology{}, Entrypoints: []architecture.Entrypoint{},
			ImportantDirectories: []architecture.Directory{},
		},
		authentication: &authentication.Findings{Mechanisms: []authentication.Mechanism{}},
		authorization: &authorization.Findings{
			Roles: []authorization.Role{}, Permissions: []authorization.Permission{},
			RolePermissions: []authorization.RolePermission{}, Enforcement: []authorization.Enforcement{},
		},
		entities: &entities.Findings{Entities: []entities.Entity{}},
		surface: &surface.Findings{
			Interfaces: []surface.Interface{}, Integrations: []surface.Integration{},
			Handlers: []surface.Handler{}, Relationships: []surface.Relationship{},
		},
		features: &features.Findings{Features: []features.Node{}},
	}
	result := func() *investigation.Result {
		return &investigation.Result{
			Status:     "completed",
			Summary:    "summary-must-not-be-canonical api-key-secret-value",
			Unresolved: []investigation.UnresolvedQuestion{},
		}
	}
	return findings, completedResults{
		architecture: result(), authentication: result(), authorization: result(),
		entities: result(), surface: result(), features: result(),
	}
}
