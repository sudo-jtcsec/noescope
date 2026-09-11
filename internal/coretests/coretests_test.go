package coretests

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

func fixtureApplication() *model.Application {
	return &model.Application{
		SchemaVersion: model.SchemaVersion,
		Metadata: model.Metadata{RunID: "run_source", Source: model.SourceMetadata{
			Root: "/repo", GitCommit: "commit-1",
		}},
		Entities: []entities.Entity{{ID: "project", Name: "Project"}, {ID: "task", Name: "Task"}},
		Surface: surface.Findings{Interfaces: []surface.Interface{
			{ID: "auth.login", Type: "web_page", Name: "Login", Description: "Sign in", Locator: surface.InterfaceLocator{Path: "/login", Method: "GET"}, Access: &surface.Access{Authentication: "not_required"}},
			{ID: "dashboard.show", Type: "web_page", Name: "Dashboard", Description: "Dashboard", Locator: surface.InterfaceLocator{Path: "/", Method: "GET"}, Access: &surface.Access{Authentication: "required"}},
			{ID: "project.list", Type: "web_page", Name: "Projects", Description: "List projects", Locator: surface.InterfaceLocator{Path: "/projects", Method: "GET"}, Access: &surface.Access{Authentication: "required"}, EntityIDs: []string{"project"}},
			{ID: "task.create", Type: "form_action", Name: "Create Task", Description: "Create task", Locator: surface.InterfaceLocator{Path: "/task/create", Method: "POST"}, Access: &surface.Access{Authentication: "required"}, EntityIDs: []string{"task"}},
			{ID: "api.task.create", Type: "api_method", Name: "Create Task API", Description: "Create task", Locator: surface.InterfaceLocator{MethodName: "createTask"}, Access: &surface.Access{Authentication: "required"}, EntityIDs: []string{"task"}},
		}},
		Features: []features.Node{{
			ID: "projects", Name: "Projects", Type: "module", Children: []features.Node{{
				ID: "projects.list", Name: "List Projects", Type: "action", InterfaceIDs: []string{"project.list"}, EntityIDs: []string{"project"},
			}},
		}, {
			ID: "tasks", Name: "Tasks", Type: "module", Children: []features.Node{{
				ID: "tasks.create", Name: "Create Task", Type: "action", Description: "Create a task", InterfaceIDs: []string{"task.create", "api.task.create"}, EntityIDs: []string{"task"},
			}},
		}},
	}
}

func fixtureRuntime() *runtimeverify.Runtime {
	return &runtimeverify.Runtime{
		SchemaVersion: runtimeverify.SchemaVersion, RuntimeID: "runtime_1", SourceRunID: "run_source",
		SourceGitCommit: "commit-1", ApplicationSchemaVersion: model.SchemaVersion,
		BaseURL: "https://example.test", Status: runtimeverify.RunStatusCompleted,
		Authentication: runtimeverify.AuthenticationObservation{
			Attempted: true, Status: runtimeverify.StatusVerified, LoginURL: "https://example.test/login",
		},
		Interfaces: []runtimeverify.InterfaceObservation{
			{InterfaceID: "auth.login", State: "unauthenticated", Status: runtimeverify.StatusVerified, HTTPStatus: 200, Title: "Login", EvidenceIDs: []string{"rev-login"}},
			{InterfaceID: "dashboard.show", State: "unauthenticated", Status: runtimeverify.StatusAuthRequired, FinalURL: "https://example.test/login", EvidenceIDs: []string{"rev-boundary"}},
			{InterfaceID: "dashboard.show", State: "authenticated", Status: runtimeverify.StatusVerified, HTTPStatus: 200, Title: "Dashboard", EvidenceIDs: []string{"rev-dashboard"}},
			{InterfaceID: "project.list", State: "unauthenticated", Status: runtimeverify.StatusAuthRequired, FinalURL: "https://example.test/login", EvidenceIDs: []string{"rev-project-auth"}},
			{InterfaceID: "project.list", State: "authenticated", Status: runtimeverify.StatusVerified, HTTPStatus: 200, Title: "Projects", EvidenceIDs: []string{"rev-projects"}},
		},
	}
}

func TestSelectCandidatesDeterministicScoringAndLimit(t *testing.T) {
	application, runtime := fixtureApplication(), fixtureRuntime()
	first, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	second, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("candidate selection is not deterministic")
	}
	if len(first) < 5 || first[0].ID != "auth.login.public" || first[1].ID != "auth.login.success" {
		t.Fatalf("unexpected priority order: %#v", candidateIDs(first))
	}
	for index := 1; index < len(first); index++ {
		if first[index-1].Safety.SelectionScore < first[index].Safety.SelectionScore {
			t.Fatalf("scores not descending: %#v", first)
		}
	}
	limited, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 3 || !reflect.DeepEqual(limited, first[:3]) {
		t.Fatalf("max_core_tests did not cap the stable order: %#v", candidateIDs(limited))
	}
}

func TestGroundSafeString(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  SafeStringGrounding
	}{
		{"exact", "Projects", SafeStringGrounding{Match: "exact", Value: "Projects", Usable: true}},
		{"redacted suffix", "Dashboard for [REDACTED]", SafeStringGrounding{Match: "prefix", Value: "Dashboard for ", Usable: true}},
		{"entirely redacted", "[REDACTED]", SafeStringGrounding{}},
		{"redacted prefix", "[REDACTED] - Project", SafeStringGrounding{Match: "contains", Value: " - Project", Usable: true}},
		{"multiple spans", "User [REDACTED] in Project [REDACTED]", SafeStringGrounding{Match: "prefix", Value: "User ", Usable: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := GroundSafeString(test.value); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("GroundSafeString(%q)=%#v, want %#v", test.value, got, test.want)
			}
		})
	}
}

func TestRuntimeTitleGroundingNeverUsesRedactionMarkerLiterally(t *testing.T) {
	application, runtime := fixtureApplication(), fixtureRuntime()
	for index := range runtime.Interfaces {
		if runtime.Interfaces[index].InterfaceID == "dashboard.show" && runtime.Interfaces[index].State == "authenticated" {
			runtime.Interfaces[index].Title = "Dashboard for [REDACTED]"
		}
	}
	candidates, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.ID != "dashboard.show.authenticated" {
			continue
		}
		for _, assertion := range candidate.Assertions {
			if assertion.Type == "page_title" {
				if assertion.Match != "prefix" || assertion.Expected != "Dashboard for " || strings.Contains(assertion.Expected, redactionMarker) {
					t.Fatalf("unsafe dashboard title assertion: %#v", assertion)
				}
				return
			}
		}
		t.Fatal("grounded dashboard title assertion missing")
	}
	t.Fatal("dashboard candidate missing")
}

func TestEntirelyRedactedRuntimeTitleOmitsAssertion(t *testing.T) {
	item := fixtureApplication().Surface.Interfaces[0]
	candidate := readCandidate(item, nil, runtimeverify.InterfaceObservation{Title: redactionMarker}, "public")
	for _, assertion := range candidate.Assertions {
		if assertion.Type == "page_title" {
			t.Fatalf("entirely redacted title produced assertion: %#v", assertion)
		}
	}
}

func TestPageTitleAssertionModesDoNotExposeLiveTitle(t *testing.T) {
	page := browser.Page{Title: "Dashboard for alice"}
	if err := evaluateAssertion(testsmodel.Assertion{
		Type: "page_title", Match: "prefix", Expected: "Dashboard for ",
	}, page, true); err != nil {
		t.Fatal(err)
	}
	if err := evaluateAssertion(testsmodel.Assertion{
		Type: "page_title", Expected: "Projects",
	}, browser.Page{Title: "Projects"}, false); err != nil {
		t.Fatal(err)
	}
	err := evaluateAssertion(testsmodel.Assertion{
		Type: "page_title", Match: "prefix", Expected: "Dashboard for ",
	}, browser.Page{Title: "Users for alice"}, true)
	if err == nil || strings.Contains(err.Error(), "alice") ||
		err.Error() != `page title did not match expected safe prefix "Dashboard for "` {
		t.Fatalf("unsafe or unexpected mismatch: %v", err)
	}
	err = evaluateAssertion(testsmodel.Assertion{
		Type: "page_title", Expected: "Projects",
	}, browser.Page{Title: "Users"}, false)
	if err == nil || strings.Contains(err.Error(), "Users") {
		t.Fatalf("exact mismatch exposed live title: %v", err)
	}
}

func TestSelectionIncludesReadOnlyAndMutatingCandidate(t *testing.T) {
	candidates, err := SelectCandidates(fixtureApplication(), fixtureRuntime(), SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]testsmodel.TestCase{}
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	if byID["project.list.authenticated"].Safety.Mutating {
		t.Fatal("runtime-verified page candidate should be read-only")
	}
	mutation, ok := byID["tasks.create"]
	if !ok || !mutation.Safety.Mutating || !mutation.Safety.RequiresOwnedData || len(mutation.Cleanup) != 1 {
		t.Fatalf("mutating candidate did not carry ownership boundary: %#v", mutation)
	}
	if len(mutation.GeneratedValues) != 1 || mutation.GeneratedValues[0].Generated != "unique_name" ||
		!reflect.DeepEqual(mutation.InterfaceIDs, []string{"api.task.create", "task.create"}) {
		t.Fatalf("mutating plan lacks generated data or complete interface trace: %#v", mutation)
	}
}

type fakeEngine struct {
	mu       *sync.Mutex
	events   *[]string
	pages    map[string]browser.Page
	login    browser.Page
	closeErr error
}

func (f *fakeEngine) Navigate(_ context.Context, target string) (browser.Page, error) {
	f.mu.Lock()
	*f.events = append(*f.events, "navigate:"+target)
	f.mu.Unlock()
	page, ok := f.pages[target]
	if !ok {
		return browser.Page{}, errors.New("unexpected URL")
	}
	return page, nil
}

func (f *fakeEngine) SubmitLogin(_ context.Context, _ browser.LoginForm, credentials browser.Credentials) (browser.Page, error) {
	f.mu.Lock()
	*f.events = append(*f.events, "login:"+credentials.Username)
	f.mu.Unlock()
	return f.login, nil
}

func (f *fakeEngine) Screenshot(context.Context, string) error { return nil }
func (f *fakeEngine) Close() error {
	f.mu.Lock()
	*f.events = append(*f.events, "close")
	f.mu.Unlock()
	return f.closeErr
}

func TestExecutorRunsSeriallyAndBlocksMutationBeforeBrowser(t *testing.T) {
	application, runtime := fixtureApplication(), fixtureRuntime()
	candidates, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	var safe []testsmodel.TestCase
	var mutation testsmodel.TestCase
	for _, candidate := range candidates {
		if candidate.ID == "auth.login.public" || candidate.ID == "project.list.authenticated" {
			safe = append(safe, candidate)
		}
		if candidate.ID == "tasks.create" {
			mutation = candidate
		}
	}
	safe = append(safe, mutation)
	events := []string{}
	mu := &sync.Mutex{}
	starts := 0
	results := ExecuteCandidates(context.Background(), safe, ExecutorOptions{
		Application: application, Runtime: runtime,
		Credentials: &browser.Credentials{Username: "admin", Password: "password-secret"},
		BrowserFactory: func(context.Context) (browser.Engine, error) {
			starts++
			return &fakeEngine{mu: mu, events: &events, pages: map[string]browser.Page{
				"https://example.test/login":    loginPage(),
				"https://example.test/projects": {FinalURL: "https://example.test/projects", HTTPStatus: 200, Title: "Projects"},
			}, login: browser.Page{FinalURL: "https://example.test/", HTTPStatus: 200, Title: "Dashboard"}}, nil
		},
	})
	if got := []string{results[0].Status, results[1].Status, results[2].Status}; !reflect.DeepEqual(got, []string{"passed", "passed", "blocked"}) {
		t.Fatalf("unexpected execution statuses: %#v", got)
	}
	if starts != 2 {
		t.Fatalf("blocked mutation started a browser: starts=%d", starts)
	}
	want := []string{
		"navigate:https://example.test/login", "close",
		"navigate:https://example.test/login", "login:admin", "navigate:https://example.test/projects", "close",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("execution was not serial: got %#v want %#v", events, want)
	}
}

func TestExecutorBlocksMissingAuthenticationBeforeBrowser(t *testing.T) {
	application, runtime := fixtureApplication(), fixtureRuntime()
	candidates, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	var authenticated testsmodel.TestCase
	for _, candidate := range candidates {
		if candidate.ID == "project.list.authenticated" {
			authenticated = candidate
			break
		}
	}
	starts := 0
	results := ExecuteCandidates(context.Background(), []testsmodel.TestCase{authenticated}, ExecutorOptions{
		Application: application, Runtime: runtime,
		AuthenticationUnavailableReason: "credential environment references are unavailable",
		BrowserFactory: func(context.Context) (browser.Engine, error) {
			starts++
			return nil, errors.New("must not start")
		},
	})
	if len(results) != 1 || results[0].Status != testsmodel.StatusBlocked || starts != 0 {
		t.Fatalf("authenticated candidate was not safely blocked: %#v starts=%d", results, starts)
	}
}

func TestGeneratedValuesAndCleanupOwnershipGuard(t *testing.T) {
	state := NewExecutionState()
	value := testsmodel.ValueReference{Generated: "unique_name", Prefix: "Noescope Test"}
	first, err := state.ResolveValue("generated.task_title", value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := state.ResolveValue("generated.task_title", value)
	if err != nil || first != second || !strings.HasPrefix(first, "Noescope Test ") {
		t.Fatalf("generated value was not stable within execution: %q %q %v", first, second, err)
	}
	cleanup := testsmodel.CleanupStep{Type: "delete_created_entity", OwnedReference: "created.task"}
	if _, err := GuardCleanup(cleanup, state); err == nil {
		t.Fatal("cleanup of an unowned object should be refused")
	}
	if err := state.TrackOwned("created.task", "runtime-task-42"); err != nil {
		t.Fatal(err)
	}
	if objectID, err := GuardCleanup(cleanup, state); err != nil || objectID != "runtime-task-42" {
		t.Fatalf("owned cleanup was not authorized: %q %v", objectID, err)
	}
}

func TestEvidenceRedactsCredentialsAndSensitiveAttributes(t *testing.T) {
	root := t.TempDir()
	store := NewEvidenceStore(root, runtimeverify.NewRedactor("admin-secret", "password-secret"))
	_, err := store.Add(EvidenceRecord{
		Kind: "test_step", TestID: "auth.login", Summary: "used admin-secret password-secret",
		URL:        "https://admin-secret:password-secret@example.test/path?token=visible",
		Attributes: map[string]string{"cookie": "session-value", "note": "password-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"admin-secret", "password-secret", "session-value", "token=visible"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q persisted in evidence: %s", secret, raw)
		}
	}
}

func TestArtifactsOnlyPromotePassedCandidatesAndPreserveInputs(t *testing.T) {
	root := t.TempDir()
	application, runtime := fixtureApplication(), fixtureRuntime()
	applicationRaw, _ := json.Marshal(application)
	runtimeRaw, _ := json.Marshal(runtime)
	applicationPath := filepath.Join(root, "application.json")
	runtimePath := filepath.Join(root, "runtime.json")
	if err := os.WriteFile(applicationPath, applicationRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, runtimeRaw, 0600); err != nil {
		t.Fatal(err)
	}
	beforeApplication, beforeRuntime := sha256.Sum256(applicationRaw), sha256.Sum256(runtimeRaw)
	candidates, err := SelectCandidates(application, runtime, SelectionOptions{MaxCandidates: 20})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(root, "admin", application, runtime, runtimeverify.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	results := []testsmodel.CandidateResult{
		{Candidate: candidates[0], Status: testsmodel.StatusPassed},
		{Candidate: candidates[len(candidates)-1], Status: testsmodel.StatusFailed, Reason: "fixture failure"},
	}
	session.Complete(results)
	paths, err := session.Write(application)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Pack.Tests) != 1 || session.Pack.Tests[0].ID != candidates[0].ID {
		t.Fatalf("failed candidate was promoted into verified pack: %#v", session.Pack.Tests)
	}
	if session.Baseline == nil || len(session.Baseline.VerifiedTestIDs) != 1 {
		t.Fatal("passing candidate did not create baseline")
	}
	for _, path := range []string{paths.Pack, paths.Markdown, paths.Execution, paths.Baseline} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("artifact missing %s: %v", path, err)
		}
	}
	if !reflect.DeepEqual(Markdown(session.Pack, session.Execution), Markdown(session.Pack, session.Execution)) {
		t.Fatal("Markdown rendering is not deterministic")
	}
	afterApplication, _ := os.ReadFile(applicationPath)
	afterRuntime, _ := os.ReadFile(runtimePath)
	if sha256.Sum256(afterApplication) != beforeApplication || sha256.Sum256(afterRuntime) != beforeRuntime {
		t.Fatal("source or runtime artifact was mutated")
	}
}

func TestSensitiveLiveTitleAbsentFromAllArtifacts(t *testing.T) {
	root := t.TempDir()
	application, runtime := fixtureApplication(), fixtureRuntime()
	redactor := runtimeverify.NewRedactor("alice", "password-secret")
	session, err := NewSession(root, "admin", application, runtime, redactor)
	if err != nil {
		t.Fatal(err)
	}
	store := NewEvidenceStore(session.Root, redactor)
	if _, err := store.Add(EvidenceRecord{
		Kind: "test_assertion", TestID: "dashboard.show.authenticated",
		Summary: "observed Dashboard for alice", Attributes: map[string]string{"title": "Dashboard for alice"},
	}); err != nil {
		t.Fatal(err)
	}
	candidate := testsmodel.TestCase{
		ID: "dashboard.show.authenticated", Name: "Dashboard", Kind: testsmodel.KindCore,
		Description: "Verify dashboard.", InterfaceIDs: []string{"dashboard.show"},
		GeneratedValues: []testsmodel.ValueReference{},
		Preconditions:   testsmodel.Preconditions{Authentication: "authenticated"},
		Steps:           []testsmodel.Step{{Type: "navigate", InterfaceID: "dashboard.show"}},
		Assertions:      []testsmodel.Assertion{{Type: "page_title", Match: "prefix", Expected: "Dashboard for "}},
		Cleanup:         []testsmodel.CleanupStep{}, Safety: testsmodel.SafetyMetadata{Classification: "safe"},
		EvidenceIDs: []string{},
	}
	session.Complete([]testsmodel.CandidateResult{{
		Candidate: candidate, Status: testsmodel.StatusFailed,
		Reason: "unexpected live title Dashboard for alice", Values: map[string]string{"observed": "alice"},
	}})
	paths, err := session.Write(application)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Pack, paths.Markdown, paths.Execution, paths.Evidence} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"alice", "password-secret"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("secret %q persisted in %s", secret, path)
			}
		}
	}
}

func TestSessionWithoutPassedCandidateDoesNotCreateBaseline(t *testing.T) {
	session, err := NewSession(t.TempDir(), "admin", fixtureApplication(), fixtureRuntime(), runtimeverify.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	session.Complete([]testsmodel.CandidateResult{{
		Candidate: testsmodel.TestCase{ID: "candidate"}, Status: testsmodel.StatusFailed,
	}})
	if session.Baseline != nil {
		t.Fatal("baseline should not exist without a verified Core Test")
	}
}

func candidateIDs(values []testsmodel.TestCase) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].ID
	}
	return result
}

func loginPage() browser.Page {
	return browser.Page{
		FinalURL: "https://example.test/login", HTTPStatus: 200, Title: "Login",
		Forms: []browser.Form{{UsernameSelector: "#username", PasswordSelector: "#password", SubmitSelector: "button"}},
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []testsmodel.CandidateResult{
		{Status: testsmodel.StatusPassed}, {Status: testsmodel.StatusBlocked},
		{Status: testsmodel.StatusFailed}, {Status: testsmodel.StatusCleanupFailed},
		{Status: testsmodel.StatusUnresolved}, {Status: testsmodel.StatusNotAttempted},
	}
	summary := summarizeResults(results)
	if summary.Candidates != 6 || summary.Passed != 1 || summary.Blocked != 1 || summary.Failed != 1 ||
		summary.CleanupFailed != 1 || summary.Unresolved != 1 || summary.NotAttempted != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestCompletedRuntimeSelectionRejectsPartial(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "runtime", "runtime_partial")
	if err := os.MkdirAll(runtimeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	runtime := fixtureRuntime()
	runtime.Status = runtimeverify.RunStatusPartial
	runtime.CompletedAt = time.Now().UTC()
	raw, _ := json.Marshal(runtime)
	if err := os.WriteFile(filepath.Join(runtimeRoot, "runtime.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "evidence.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCompletedRuntime(root, "runtime_partial", fixtureApplication()); err == nil {
		t.Fatal("partial runtime should not be accepted")
	}
}
