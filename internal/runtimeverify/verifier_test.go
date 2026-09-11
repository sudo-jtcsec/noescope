package runtimeverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

type fakeBrowser struct {
	loggedIn   bool
	loginWorks bool
	navigated  []string
	closed     bool
}

func (f *fakeBrowser) Navigate(_ context.Context, target string) (browser.Page, error) {
	f.navigated = append(f.navigated, target)
	switch target {
	case "https://app.example/", "https://app.example/login":
		return loginPage(target), nil
	case "https://app.example/projects":
		return browser.Page{
			RequestedURL: target, FinalURL: target, HTTPStatus: 200, Ready: true, Title: "Projects",
			Elements: []browser.Element{{Role: "heading", Text: "Projects"}},
			Links:    []browser.Link{{URL: "https://app.example/project/4", Text: "Project Four"}},
			Network:  []browser.NetworkObservation{{Method: "GET", URL: target, Status: 200, Type: "Document"}},
		}, nil
	case "https://app.example/project/4":
		return browser.Page{RequestedURL: target, FinalURL: target, HTTPStatus: 200, Ready: true, Title: "Project Four"}, nil
	case "https://app.example/admin":
		if !f.loggedIn {
			return loginPage("https://app.example/login"), nil
		}
		return browser.Page{RequestedURL: target, FinalURL: target, HTTPStatus: 200, Ready: true, Title: "Admin"}, nil
	default:
		return browser.Page{RequestedURL: target}, errors.New("unexpected URL")
	}
}

func (f *fakeBrowser) SubmitLogin(_ context.Context, _ browser.LoginForm, credentials browser.Credentials) (browser.Page, error) {
	if f.loginWorks && credentials.Username == "alice" && credentials.Password == "super-secret" {
		f.loggedIn = true
		return browser.Page{
			FinalURL: "https://app.example/dashboard", HTTPStatus: 200, Ready: true, Title: "Dashboard",
			Elements: []browser.Element{{Role: "link", Text: "Logout"}},
			Cookies:  []browser.Cookie{{Name: "session", HTTPOnly: true}},
		}, nil
	}
	return loginPage("https://app.example/login"), nil
}

func (f *fakeBrowser) Screenshot(_ context.Context, path string) error {
	return os.WriteFile(path, []byte("png"), 0600)
}

func (f *fakeBrowser) Close() error { f.closed = true; return nil }

func loginPage(target string) browser.Page {
	return browser.Page{
		RequestedURL: target, FinalURL: target, HTTPStatus: 200, Ready: true, Title: "Login",
		Forms: []browser.Form{{
			Action: "/login", Method: "POST", UsernameField: "username", PasswordField: "password",
			UsernameSelector: "#username", PasswordSelector: "#password", SubmitSelector: "button",
		}},
	}
}

func TestVerifyReachabilityLoginReadOnlyInterfacesRedirectAndBinding(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	redactor := NewRedactor("alice", "super-secret")
	fake := &fakeBrowser{loginWorks: true}
	var logs strings.Builder
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		MaxInterfaces: 10,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(&logs, format+"\n", args...)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !session.Runtime.Application.Reachable || session.Runtime.Authentication.Status != StatusVerified ||
		!fake.closed || session.Runtime.Status != RunStatusCompleted {
		t.Fatalf("reachability/authentication failed: %#v", session.Runtime)
	}
	byKey := map[string]InterfaceObservation{}
	for _, item := range session.Runtime.Interfaces {
		byKey[item.InterfaceID+"/"+item.State] = item
	}
	if byKey["web.projects/unauthenticated"].Status != StatusVerified {
		t.Fatalf("public read interface was not verified: %#v", byKey)
	}
	if byKey["web.admin/unauthenticated"].Status != StatusAuthRequired ||
		byKey["web.admin/authenticated"].Status != StatusVerified {
		t.Fatalf("authentication redirect/retry not represented: %#v", byKey)
	}
	if byKey["web.project.show/unauthenticated"].Status != StatusVerified ||
		byKey["web.project.show/unauthenticated"].RequestedURL != "https://app.example/project/4" {
		t.Fatalf("observed route binding not used: %#v", byKey["web.project.show/unauthenticated"])
	}
	if byKey["web.task.create/not_attempted"].Status != StatusNotAttempted ||
		byKey["web.task.create/not_attempted"].Safety != SafetyMutating {
		t.Fatalf("mutating interface was attempted: %#v", byKey["web.task.create/not_attempted"])
	}
	if strings.Contains(logs.String(), "alice") || strings.Contains(logs.String(), "super-secret") {
		t.Fatalf("runtime logs contain credentials: %s", logs.String())
	}

	jsonPath, markdownPath, err := session.Write()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{jsonPath, markdownPath, filepath.Join(session.Root, "evidence.jsonl")} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "super-secret") {
			t.Fatalf("runtime artifact %s contains credentials", path)
		}
	}
}

func TestVerifyAuthenticationFailureIsExplicit(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeBrowser{loginWorks: false}
	redactor := NewRedactor("bad-user", "bad-secret")
	if err := Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "bad-user", Password: "bad-secret"},
		MaxInterfaces: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if session.Runtime.Authentication.Status != StatusUnverified ||
		!strings.Contains(session.Runtime.Authentication.Reason, "login form remained") {
		t.Fatalf("authentication failure not represented: %#v", session.Runtime.Authentication)
	}
}

func TestVerifyInterfaceLimitSkipsRemainingSafeInterfaces(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeBrowser{loginWorks: true}
	redactor := NewRedactor("alice", "super-secret")
	if err := Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		MaxInterfaces: 1,
	}); err != nil {
		t.Fatal(err)
	}
	byID := map[string]InterfaceObservation{}
	for _, item := range session.Runtime.Interfaces {
		if item.State == "not_attempted" {
			byID[item.InterfaceID] = item
		}
	}
	if !strings.Contains(byID["web.admin"].Reason, "limit of 1") ||
		!strings.Contains(byID["web.project.show"].Reason, "limit of 1") {
		t.Fatalf("safe interface limit was not explicit: %#v", byID)
	}
}

type unreachableBrowser struct{ closed bool }

func (b *unreachableBrowser) Navigate(context.Context, string) (browser.Page, error) {
	return browser.Page{}, errors.New("connection refused")
}
func (b *unreachableBrowser) SubmitLogin(context.Context, browser.LoginForm, browser.Credentials) (browser.Page, error) {
	return browser.Page{}, errors.New("not reached")
}
func (b *unreachableBrowser) Screenshot(context.Context, string) error { return nil }
func (b *unreachableBrowser) Close() error                             { b.closed = true; return nil }

func TestVerifyApplicationReachabilityFailureProducesCompleteOverlay(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	browser := &unreachableBrowser{}
	redactor := NewRedactor()
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: browser, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
	})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("expected reachability failure, got %v", err)
	}
	if session.Runtime.Application.Reachable || session.Runtime.Application.Status != StatusRuntimeError ||
		len(session.Runtime.Interfaces) != len(application.Surface.Interfaces) || !browser.closed ||
		session.Runtime.Status != RunStatusFailed {
		t.Fatalf("incomplete reachability overlay: %#v", session.Runtime)
	}
}

type observationFailureBrowser struct {
	fakeBrowser
	insufficientAuthEvidence bool
}

func (b *observationFailureBrowser) Navigate(ctx context.Context, target string) (browser.Page, error) {
	page, err := b.fakeBrowser.Navigate(ctx, target)
	if err == nil {
		page.ObservationErrors = append(page.ObservationErrors, browser.BrowserObservationError{
			Operation: "cookies", Err: errors.New("invalid context"),
		})
	}
	return page, err
}

func (b *observationFailureBrowser) SubmitLogin(
	ctx context.Context,
	login browser.LoginForm,
	credentials browser.Credentials,
) (browser.Page, error) {
	if b.insufficientAuthEvidence {
		return browser.Page{
			RequestedURL: login.PageURL, FinalURL: login.PageURL,
			HTTPStatus: 200, Ready: true, Title: "Welcome",
			ObservationErrors: []browser.BrowserObservationError{{
				Operation: "cookies", Err: errors.New("invalid context"),
			}},
		}, nil
	}
	page, err := b.fakeBrowser.SubmitLogin(ctx, login, credentials)
	if err == nil {
		page.Cookies = nil
		page.ObservationErrors = append(page.ObservationErrors, browser.BrowserObservationError{
			Operation: "cookies", Err: errors.New("invalid context"),
		})
	}
	return page, err
}

func TestCookieObservationFailureDoesNotOverrideReachabilityOrUIAuthentication(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	fake := &observationFailureBrowser{fakeBrowser: fakeBrowser{loginWorks: true}}
	redactor := NewRedactor("alice", "super-secret")
	if err := Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		MaxInterfaces: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if !session.Runtime.Application.Reachable || session.Runtime.Application.Status != StatusVerified {
		t.Fatalf("optional cookie failure changed reachability: %#v", session.Runtime.Application)
	}
	if session.Runtime.Authentication.Status != StatusVerified {
		t.Fatalf("UI evidence did not verify authentication: %#v", session.Runtime.Authentication)
	}
	if session.Runtime.Status != RunStatusPartial || len(session.Runtime.ObservationErrors) == 0 {
		t.Fatalf("optional observation failure was not retained: %#v", session.Runtime)
	}
}

func TestAuthenticationUnknownWhenCookieInspectionFailsWithoutOtherEvidence(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	fake := &observationFailureBrowser{
		fakeBrowser: fakeBrowser{loginWorks: true}, insufficientAuthEvidence: true,
	}
	redactor := NewRedactor("alice", "super-secret")
	if err := Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		MaxInterfaces: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if session.Runtime.Authentication.Status != StatusUnknown ||
		!strings.Contains(session.Runtime.Authentication.Reason, "cookie inspection failed") {
		t.Fatalf("insufficient authentication evidence was misclassified: %#v", session.Runtime.Authentication)
	}
}

func TestRuntimeArtifactsDoNotChangeSourceApplication(t *testing.T) {
	application := runtimeApplicationFixture()
	sourcePath := filepath.Join(t.TempDir(), "application.json")
	original, err := json.MarshalIndent(application, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, original, 0644); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	session.Runtime.Features = FeatureCoverage(application, nil)
	if _, _, err := session.Write(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("runtime artifact generation changed source application.json")
	}
}

func TestLoginCandidateURLsUseCanonicalSurfaceHints(t *testing.T) {
	application := runtimeApplicationFixture()
	application.Identity.Authentication.Mechanisms[0].LoginEntrypoints = []string{"web.login"}
	application.Surface.Interfaces = append(application.Surface.Interfaces, surface.Interface{
		ID: "web.login", Type: "web_page", Name: "Sign in",
		Locator: surface.InterfaceLocator{Path: "/session/login"},
	})
	urls := loginCandidateURLs(application, "https://app.example/")
	if len(urls) != 1 || urls[0] != "https://app.example/session/login" {
		t.Fatalf("surface login hint was not used: %v", urls)
	}
}

func runtimeApplicationFixture() *model.Application {
	public := &surface.Access{Authentication: "not_required"}
	required := &surface.Access{Authentication: "required"}
	interfaces := []surface.Interface{
		{ID: "web.projects", Type: "web_page", Locator: surface.InterfaceLocator{Method: "GET", Path: "/projects"}, Access: public},
		{ID: "web.project.show", Type: "web_page", Locator: surface.InterfaceLocator{Method: "GET", Path: "/project/{project_id}"}, Access: public},
		{ID: "web.admin", Type: "web_page", Locator: surface.InterfaceLocator{Method: "GET", Path: "/admin"}, Access: required},
		{ID: "web.task.create", Type: "form_action", Locator: surface.InterfaceLocator{Method: "POST", Path: "/task"}, Access: required},
		{ID: "api.task.get", Type: "api_endpoint", Locator: surface.InterfaceLocator{MethodName: "getTask", TransportPath: "/jsonrpc"}, Access: required},
	}
	return &model.Application{
		SchemaVersion: model.SchemaVersion,
		Metadata:      model.Metadata{RunID: "run_source", Source: model.SourceMetadata{GitCommit: "commit-one"}},
		Identity: model.Identity{Authentication: authentication.Findings{
			AuthenticationPresent: true,
			Mechanisms: []authentication.Mechanism{{
				ID: "password", Type: "form_session", LoginEntrypoints: []string{"/login (GET)"},
			}},
		}},
		Surface: surface.Findings{Interfaces: interfaces},
		Features: []features.Node{{
			ID: "projects", Type: "module", Children: []features.Node{
				{ID: "projects.list", Type: "action", InterfaceIDs: []string{"web.projects"}},
				{ID: "projects.view", Type: "action", InterfaceIDs: []string{"web.project.show"}},
			},
		}, {
			ID: "tasks", Type: "module", Children: []features.Node{{
				ID: "tasks.create", Type: "action", InterfaceIDs: []string{"web.task.create"},
			}},
		}},
	}
}
