package coretests

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

func workflowFixtureApplication() *model.Application {
	application := fixtureApplication()
	application.Entities = []entities.Entity{
		{ID: "project", Name: "Project", Relationships: []entities.Relationship{{
			Type: "has_many", TargetEntityID: "task",
		}}},
		{ID: "task", Name: "Task", Relationships: []entities.Relationship{{
			Type: "belongs_to", TargetEntityID: "project",
		}}},
	}
	application.Surface.Interfaces = []surface.Interface{
		workflowInterface("auth.login", "web_page", "/login", nil),
		workflowInterface("project.create", "form_action", "/project/create", []string{"project"}),
		workflowInterface("project.view", "web_page", "/project/{project_id}", []string{"project"}),
		workflowInterface("project.task.create", "web_page", "/project/{project_id}/task/create", []string{"project", "task"}),
		workflowInterface("task.show", "web_page", "/task/{task_id}", []string{"task"}),
		workflowInterface("task.edit", "web_page", "/task/{task_id}/edit", []string{"task"}),
		workflowInterface("task.update", "form_action", "/task/{task_id}/update", []string{"task"}),
		workflowInterface("task.remove.confirm", "web_page", "/task/{task_id}/remove", []string{"task"}),
		workflowInterface("project.remove", "form_action", "/project/{project_id}/remove", []string{"project"}),
	}
	application.Features = []features.Node{{
		ID: "projects", Name: "Projects", Type: "module", Children: []features.Node{
			workflowAction("project.lifecycle.create", "Create Project", []string{"project"}, "project.create"),
			workflowAction("project.board.view", "View Project", []string{"project"}, "project.view"),
			workflowAction("project.tasks.create", "Create Task", []string{"project", "task"}, "project.task.create"),
			workflowAction("project.lifecycle.remove", "Remove Project", []string{"project"}, "project.remove"),
		},
	}, {
		ID: "tasks", Name: "Tasks", Type: "module", Children: []features.Node{
			workflowAction("task.view.details", "View Task Details", []string{"task"}, "task.show"),
			workflowAction("task.edit.form", "Edit Task", []string{"task"}, "task.edit"),
			workflowAction("task.edit.save", "Update Task", []string{"task"}, "task.update"),
			workflowAction("task.remove.confirm", "Remove Task", []string{"task"}, "task.remove.confirm"),
		},
	}}
	return application
}

func workflowInterface(id, kind, path string, entityIDs []string) surface.Interface {
	return surface.Interface{
		ID: id, Type: kind, Name: id, Description: id,
		Locator: surface.InterfaceLocator{Path: path}, EntityIDs: entityIDs, Confidence: 1,
	}
}

func workflowAction(id, name string, entityIDs []string, interfaceID string) features.Node {
	return features.Node{
		ID: id, Name: name, Type: "action", Description: name,
		EntityIDs: entityIDs, InterfaceIDs: []string{interfaceID}, Confidence: 1,
	}
}

func TestPlanOwnedLifecycleUsesCanonicalParentChildWorkflow(t *testing.T) {
	plan, err := PlanOwnedLifecycle(workflowFixtureApplication())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Test.ID != "core.project_task.lifecycle" || plan.ParentEntity.ID != "project" || plan.ChildEntity.ID != "task" {
		t.Fatalf("unexpected lifecycle selection: %#v", plan)
	}
	wantInterfaces := []string{
		"project.create", "project.remove", "project.task.create", "project.view",
		"task.edit", "task.remove.confirm", "task.show", "task.update",
	}
	if !reflect.DeepEqual(plan.Test.InterfaceIDs, wantInterfaces) {
		t.Fatalf("unexpected canonical interfaces: got %#v want %#v", plan.Test.InterfaceIDs, wantInterfaces)
	}
	if got := []string{plan.Test.Cleanup[0].OwnedReference, plan.Test.Cleanup[1].OwnedReference}; !reflect.DeepEqual(got, []string{"created.task", "created.project"}) {
		t.Fatalf("cleanup is not child-first: %#v", got)
	}
	second, err := PlanOwnedLifecycle(workflowFixtureApplication())
	if err != nil || !reflect.DeepEqual(plan, second) {
		t.Fatalf("lifecycle planning is not deterministic: %v", err)
	}
}

func TestFilterTestCandidatesSelectsOnlyRequestedTest(t *testing.T) {
	plan, err := PlanOwnedLifecycle(workflowFixtureApplication())
	if err != nil {
		t.Fatal(err)
	}
	regular := []testsmodel.TestCase{{ID: "dashboard.view"}}
	selected, err := FilterTestCandidates(regular, plan, plan.Test.ID)
	if err != nil || len(selected) != 1 || selected[0].ID != plan.Test.ID {
		t.Fatalf("workflow filter failed: %#v %v", selected, err)
	}
	selected, err = FilterTestCandidates(regular, plan, "dashboard.view")
	if err != nil || len(selected) != 1 || selected[0].ID != "dashboard.view" {
		t.Fatalf("regular filter failed: %#v %v", selected, err)
	}
	if _, err := FilterTestCandidates(regular, plan, "missing.test"); err == nil {
		t.Fatal("missing filter should fail")
	}
}

type workflowFakeBrowser struct {
	events             []string
	parentName         string
	childTitle         string
	updatedTitle       string
	parentCreationSeen bool
	cleanupUnavailable bool
}

func (f *workflowFakeBrowser) Navigate(_ context.Context, target string) (browser.Page, error) {
	f.events = append(f.events, "navigate:"+target)
	switch target {
	case "https://example.test/login":
		return loginPage(), nil
	case "https://example.test/project/create":
		return mutationFormPage(target, "name"), nil
	case "https://example.test/project/41/task/create":
		return mutationFormPage(target, "title"), nil
	case "https://example.test/task/73/edit":
		return mutationFormPage(target, "title"), nil
	case "https://example.test/task/73/remove", "https://example.test/project/41/remove":
		return browser.Page{FinalURL: target, HTTPStatus: 200, Links: []browser.Link{{
			URL: target + "?confirm=yes&csrf_token=SECRET", Text: "Yes", Selector: "#confirm",
		}}}, nil
	case "https://example.test/task/73", "https://example.test/project/41":
		if f.cleanupUnavailable {
			return browser.Page{FinalURL: target, HTTPStatus: 200, Title: "Still exists"}, nil
		}
		return browser.Page{FinalURL: target, HTTPStatus: 404, Title: "Not found"}, nil
	default:
		return browser.Page{}, errors.New("unexpected URL: " + target)
	}
}

func (f *workflowFakeBrowser) SubmitLogin(_ context.Context, _ browser.LoginForm, _ browser.Credentials) (browser.Page, error) {
	f.events = append(f.events, "login")
	return browser.Page{FinalURL: "https://example.test/", HTTPStatus: 200, Title: "Dashboard"}, nil
}

func (f *workflowFakeBrowser) SubmitForm(_ context.Context, submission browser.FormSubmission) (browser.Page, error) {
	if len(submission.Entries) != 1 || strings.Contains(strings.ToLower(submission.Entries[0].Selector), "csrf") {
		return browser.Page{}, errors.New("unsafe form submission")
	}
	value := submission.Entries[0].Value
	f.events = append(f.events, "submit:"+submission.PageURL)
	switch submission.PageURL {
	case "https://example.test/project/create":
		f.parentName = value
		if !f.parentCreationSeen {
			return browser.Page{FinalURL: "https://example.test/projects", HTTPStatus: 200,
				Elements: []browser.Element{{Text: value}}}, nil
		}
		return browser.Page{FinalURL: "https://example.test/project/41", HTTPStatus: 200,
			Elements: []browser.Element{{Text: value}}}, nil
	case "https://example.test/project/41/task/create":
		f.childTitle = value
		return browser.Page{FinalURL: "https://example.test/task/73", HTTPStatus: 200,
			Elements: []browser.Element{{Text: value}}}, nil
	case "https://example.test/task/73/edit":
		f.updatedTitle = value
		return browser.Page{FinalURL: "https://example.test/task/73", HTTPStatus: 200,
			Elements: []browser.Element{{Text: value}}}, nil
	default:
		return browser.Page{}, errors.New("unexpected form submission")
	}
}

func (f *workflowFakeBrowser) Activate(_ context.Context, activation browser.Activation) (browser.Page, error) {
	f.events = append(f.events, "delete:"+activation.PageURL)
	return browser.Page{FinalURL: "https://example.test/", HTTPStatus: 200}, nil
}

func (f *workflowFakeBrowser) Screenshot(context.Context, string) error { return nil }
func (f *workflowFakeBrowser) Close() error {
	f.events = append(f.events, "close")
	return nil
}

func mutationFormPage(target, field string) browser.Page {
	return browser.Page{FinalURL: target, HTTPStatus: 200, Forms: []browser.Form{{
		Selector: "#form", Action: target, Method: "POST", SubmitSelector: "#submit",
		Controls: []browser.FormControl{{ID: field, Name: field, Type: "text", Selector: "#" + field}},
	}}}
}

func workflowOptions(application *model.Application, fake *workflowFakeBrowser) WorkflowExecutorOptions {
	return WorkflowExecutorOptions{ExecutorOptions: ExecutorOptions{
		Application: application, Runtime: fixtureRuntime(),
		Credentials:      &browser.Credentials{Username: "fixture-user", Password: "fixture-password"},
		MutationsEnabled: true, Cleanup: "always",
		BrowserFactory: func(context.Context) (browser.Engine, error) { return fake, nil },
	}, ExecutionID: "execution-1"}
}

func TestOwnedLifecycleMutationDisabledBeforeBrowser(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	options := workflowOptions(application, &workflowFakeBrowser{})
	options.MutationsEnabled = false
	options.BrowserFactory = func(context.Context) (browser.Engine, error) {
		started = true
		return nil, errors.New("must not start")
	}
	result := ExecuteOwnedLifecycle(context.Background(), plan, options)
	if result.Status != testsmodel.StatusBlocked || result.Reason != "testing.mutations.enabled=false" || started {
		t.Fatalf("mutation permission boundary failed: %#v started=%v", result, started)
	}
}

func TestOwnedLifecyclePassesAndCleansInDependencyOrder(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	fake := &workflowFakeBrowser{parentCreationSeen: true}
	result := ExecuteOwnedLifecycle(context.Background(), plan, workflowOptions(application, fake))
	if result.Status != testsmodel.StatusPassed || len(result.OwnedObjects) != 2 {
		t.Fatalf("workflow did not pass with two owned objects: %#v", result)
	}
	if fake.parentName == fake.childTitle || fake.childTitle == fake.updatedTitle ||
		!strings.HasPrefix(fake.parentName, "Noescope Test Project ") ||
		!strings.HasPrefix(fake.childTitle, "Noescope Test Task ") {
		t.Fatalf("generated symbolic values were not unique and reusable: %#v", result.Values)
	}
	wantDeletes := []string{
		"delete:https://example.test/task/73/remove",
		"delete:https://example.test/project/41/remove",
	}
	var deletes []string
	for _, event := range fake.events {
		if strings.HasPrefix(event, "delete:") {
			deletes = append(deletes, event)
		}
	}
	if !reflect.DeepEqual(deletes, wantDeletes) {
		t.Fatalf("cleanup order was not child then parent: got %#v", deletes)
	}
	for _, object := range result.OwnedObjects {
		if object.ExecutionID != "execution-1" || object.CreatedByTestID != plan.Test.ID ||
			object.RuntimeIdentifier == "" || object.CleanupStatus != "verified" {
			t.Fatalf("invalid ownership transition: %#v", object)
		}
	}
}

func TestOwnershipEstablishedOnlyAfterConfirmedCreation(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	fake := &workflowFakeBrowser{parentCreationSeen: false}
	result := ExecuteOwnedLifecycle(context.Background(), plan, workflowOptions(application, fake))
	if result.Status != testsmodel.StatusFailed || len(result.OwnedObjects) != 0 {
		t.Fatalf("ambiguous creation incorrectly established ownership: %#v", result)
	}
	for _, event := range fake.events {
		if strings.HasPrefix(event, "delete:") {
			t.Fatalf("ambiguous object was deleted: %#v", fake.events)
		}
	}
}

func TestOwnedLifecycleFailureStillCleansOnlyOwnedObjects(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	fake := &workflowFakeBrowser{parentCreationSeen: true}
	options := workflowOptions(application, fake)
	options.Hooks.AfterChildCreation = func() error { return errors.New("simulated post-create failure") }
	result := ExecuteOwnedLifecycle(context.Background(), plan, options)
	if result.Status != testsmodel.StatusFailed || result.WorkflowFailure != "simulated post-create failure" {
		t.Fatalf("workflow failure semantics incorrect: %#v", result)
	}
	var deletes []string
	for _, event := range fake.events {
		if strings.HasPrefix(event, "delete:") {
			deletes = append(deletes, event)
		}
	}
	want := []string{"delete:https://example.test/task/73/remove", "delete:https://example.test/project/41/remove"}
	if !reflect.DeepEqual(deletes, want) {
		t.Fatalf("failure cleanup did not run safely: got %#v", deletes)
	}
	for _, event := range fake.events {
		if strings.Contains(event, "fixture") {
			t.Fatalf("non-owned fixture object was touched: %q", event)
		}
	}
}

func TestOwnedLifecycleCleanupVerificationFailureIsProminent(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	fake := &workflowFakeBrowser{parentCreationSeen: true, cleanupUnavailable: true}
	result := ExecuteOwnedLifecycle(context.Background(), plan, workflowOptions(application, fake))
	if result.Status != testsmodel.StatusCleanupFailed || result.CleanupFailure == "" {
		t.Fatalf("cleanup verification failure was not prominent: %#v", result)
	}
	var deletes int
	for _, event := range fake.events {
		if strings.HasPrefix(event, "delete:") {
			deletes++
		}
	}
	if deletes != 2 {
		t.Fatalf("cleanup stopped before all proven-owned objects were attempted: %#v", fake.events)
	}
	session, err := NewSession(t.TempDir(), "admin", application, fixtureRuntime(), nil)
	if err != nil {
		t.Fatal(err)
	}
	session.Complete([]testsmodel.CandidateResult{result})
	if len(session.Pack.Tests) != 0 {
		t.Fatal("cleanup-failed workflow was promoted")
	}
}

func TestCleanupRedirectToLoginIsNotProofOfDeletion(t *testing.T) {
	page := loginPage()
	page.FinalURL = "https://example.test/login"
	if objectUnavailable(page, "https://example.test/task/73") {
		t.Fatal("authentication redirect was accepted as cleanup verification")
	}
}

func TestOwnershipRejectsDifferentExecution(t *testing.T) {
	state := NewExecutionStateFor("execution-a", "test-a")
	if err := state.EstablishOwned("created.task", "task", "73", nil, nil); err != nil {
		t.Fatal(err)
	}
	state.executionID = "execution-b"
	if _, err := state.RequireOwned("created.task"); err == nil {
		t.Fatal("object owned by another execution was accepted")
	}
}

func TestSeededBaselineRetainsPriorVerifiedTests(t *testing.T) {
	application := workflowFixtureApplication()
	plan, err := PlanOwnedLifecycle(application)
	if err != nil {
		t.Fatal(err)
	}
	prior := &testsmodel.TestPack{Tests: []testsmodel.TestCase{{ID: "prior.read", Name: "Prior", Kind: testsmodel.KindCore}}}
	session, err := NewSession(t.TempDir(), "admin", application, fixtureRuntime(), nil)
	if err != nil {
		t.Fatal(err)
	}
	session.SeedVerifiedTests(prior)
	session.Complete([]testsmodel.CandidateResult{{Candidate: plan.Test, Status: testsmodel.StatusPassed}})
	if got := session.Baseline.VerifiedTestIDs; !reflect.DeepEqual(got, []string{"core.project_task.lifecycle", "prior.read"}) {
		t.Fatalf("baseline did not retain prior verified test: %#v", got)
	}
}
