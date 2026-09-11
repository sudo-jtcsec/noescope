package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/model"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

func TestLoadStageOutputRejectsMalformedCompletedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "surface.json")
	if err := os.WriteFile(path, []byte(`{"status":"completed","findings":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadStageOutput[surface.Findings](path); err == nil ||
		!strings.Contains(err.Error(), "expected object") {
		t.Fatalf("expected malformed completed output rejection, got %v", err)
	}
}

func TestResumeExtendsSurfaceToFeaturesWithoutCallingCompletedStages(t *testing.T) {
	runRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(runRoot, "output"), 0755); err != nil {
		t.Fatal(err)
	}
	evidenceStore := evidence.NewStore(runRoot)
	records, err := evidenceStore.AddDrafts("fixture", []tools.EvidenceDraft{
		{Kind: "file", Path: "auth.php", Summary: "authentication conclusion"},
		{Kind: "file", Path: "authz.php", Summary: "authorization conclusion"},
	})
	if err != nil {
		t.Fatal(err)
	}

	architectureFindings := &architecture.Findings{
		Languages: []architecture.Technology{}, Formats: []architecture.Technology{},
		Frameworks: []architecture.Technology{}, Libraries: []architecture.Technology{},
		Databases: []architecture.Technology{}, WebServers: []architecture.Technology{},
		ExternalInterfaces: []architecture.Technology{}, Entrypoints: []architecture.Entrypoint{},
		ImportantDirectories: []architecture.Directory{},
		ArchitectureStyle:    architecture.Statement{EvidenceIDs: []string{}},
	}
	authenticationFindings := &authentication.Findings{
		AuthenticationPresent: false, Confidence: 0.9,
		EvidenceIDs: []string{records[0].ID}, Mechanisms: []authentication.Mechanism{},
	}
	authorizationFindings := &authorization.Findings{
		AuthorizationPresent: false, Confidence: 0.9,
		EvidenceIDs: []string{records[1].ID}, Roles: []authorization.Role{},
		Permissions: []authorization.Permission{}, RolePermissions: []authorization.RolePermission{},
		Enforcement: []authorization.Enforcement{},
	}
	entityFindings := &entities.Findings{Entities: []entities.Entity{}}
	surfaceFindings := &surface.Findings{
		Interfaces: []surface.Interface{}, Integrations: []surface.Integration{},
		Handlers: []surface.Handler{}, Relationships: []surface.Relationship{},
	}
	completed := &investigation.Result{Status: "completed", Summary: "validated"}
	for name, findings := range map[string]any{
		"architecture.json":   architectureFindings,
		"authentication.json": authenticationFindings,
		"authorization.json":  authorizationFindings,
		"entities.json":       entityFindings,
		"surface.json":        surfaceFindings,
	} {
		if err := writeResult(outputPath(runRoot, name), completed, findings); err != nil {
			t.Fatal(err)
		}
	}

	manifest := &runpkg.Run{
		SchemaVersion: runpkg.SchemaVersion, ID: "run_existing", Command: "discover",
		RepositoryRoot: "/repo", RepositoryCommit: "commit-one", Through: "features",
		CompletedStages: []string{
			string(StageArchitecture), string(StageAuthentication),
			string(StageAuthorization), string(StageEntities), string(StageSurface),
		},
		Surface: map[string]runpkg.SurfaceShardState{}, Root: runRoot,
	}
	if err := runpkg.Save(manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"application.json", "application.md"} {
		if err := os.WriteFile(outputPath(runRoot, name), []byte("stale artifact"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	var requests []llm.ChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request llm.ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(llm.ChatResponse{Choices: []llm.Choice{{
			Message:      llm.Message{Role: "assistant", Content: `{"status":"completed","summary":"done","findings":{"features":[]}}`},
			FinishReason: "stop",
		}}})
	}))
	defer server.Close()
	runner := investigation.NewRunner(
		llm.NewClient(server.URL, "", "test-model"), tools.NewRegistry(), evidenceStore,
	)
	var output bytes.Buffer
	if err := resumeThrough(
		context.Background(), runner, runRoot, &output, StageFeatures,
		model.Metadata{RunID: manifest.ID, Source: model.SourceMetadata{GitCommit: "commit-one"}},
		manifest, false, false,
	); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) == 0 {
		t.Fatal("missing Feature LLM call")
	}
	for _, request := range requests {
		if len(request.Messages) < 2 || !strings.Contains(request.Messages[1].Content, "top-level user/client-recognizable") {
			t.Fatal("a completed canonical stage invoked the LLM")
		}
	}
	for _, stage := range []string{"architecture", "authentication", "authorization", "entities", "surface"} {
		if !strings.Contains(output.String(), "["+stage+"] reused validated canonical stage output") {
			t.Fatalf("missing reuse log for %s:\n%s", stage, output.String())
		}
	}
	if manifest.ID != "run_existing" || !manifest.StageCompleted(string(StageFeatures)) {
		t.Fatalf("extended run identity/state changed: %#v", manifest)
	}
	for _, name := range []string{"features.json", "application.json", "application.md"} {
		raw, err := os.ReadFile(outputPath(runRoot, name))
		if err != nil {
			t.Fatalf("extended resume did not regenerate %s: %v", name, err)
		}
		if string(raw) == "stale artifact" {
			t.Fatalf("extended resume left stale %s in place", name)
		}
	}
}

func TestFeatureInterfaceMappingTelemetry(t *testing.T) {
	var output bytes.Buffer
	logFeatureInterfaceMappings(
		&output,
		&features.Findings{Features: []features.Node{{
			ID: "tasks.create", Type: "action", InterfaceIDs: []string{"api.task.create"},
		}}},
		&surface.Findings{Interfaces: []surface.Interface{{
			ID: "api.task.create", Type: "api_endpoint",
			Locator: surface.InterfaceLocator{MethodName: "task.create"},
		}}},
	)
	if output.String() != "[features] interface mapping:\n  actions: 1\n  concrete mapped: 1\n  root-only: 0\n  unmapped: 0\n[features] concrete interface coverage:\n  candidate interfaces: 1\n  referenced by feature tree: 1\n  unreferenced: 0\n" {
		t.Fatalf("unexpected interface mapping telemetry: %q", output.String())
	}
}
