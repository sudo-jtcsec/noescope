package portabletests

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

func portableFixture() *Bundle {
	public := Test{SchemaVersion: SchemaVersion, ID: "auth.login.public", Name: "Login <Public>", Kind: "core",
		Description: "Show the public login page.", Identity: "admin", InterfaceIDs: []string{"auth.login"},
		Interfaces:    []Interface{{ID: "auth.login", Type: "web_page", Name: "Login", Path: "/login", Method: "GET"}},
		Preconditions: Preconditions{Authentication: "unauthenticated"},
		Steps:         []Step{{Type: "navigate", InterfaceID: "auth.login"}, {Type: "observe"}},
		Assertions:    []Assertion{{Type: "http_status", HTTPStatus: 200}, {Type: "page_title", Expected: "Login"}, {Type: "not_authenticated"}},
		Safety:        Safety{Classification: "safe"}, EvidenceIDs: []string{}, GeneratedValues: []ValueReference{}, Cleanup: []CleanupStep{},
	}
	authenticated := Test{SchemaVersion: SchemaVersion, ID: "dashboard.show.authenticated", Name: "Dashboard", Kind: "core",
		Description: "Show the authenticated dashboard.", Identity: "admin", InterfaceIDs: []string{"dashboard.show"},
		Interfaces:    []Interface{{ID: "dashboard.show", Type: "web_page", Name: "Dashboard", Path: "/dashboard", Method: "GET"}},
		Preconditions: Preconditions{Authentication: "authenticated"},
		Steps:         []Step{{Type: "navigate", InterfaceID: "dashboard.show"}, {Type: "observe"}},
		Assertions:    []Assertion{{Type: "http_status", HTTPStatus: 200}, {Type: "authenticated"}},
		Safety:        Safety{Classification: "safe"}, EvidenceIDs: []string{}, GeneratedValues: []ValueReference{}, Cleanup: []CleanupStep{},
	}
	mutation := Test{SchemaVersion: SchemaVersion, ID: "core.parent_child.lifecycle", Name: "Owned lifecycle", Kind: "core",
		Description: "Create and clean owned data.", Identity: "admin", InterfaceIDs: []string{"parent.create"},
		Interfaces:    []Interface{{ID: "parent.create", Type: "form_action", Name: "Create", Path: "/parent/create"}},
		Preconditions: Preconditions{Authentication: "authenticated"}, Steps: []Step{{Type: "navigate", InterfaceID: "parent.create"}},
		Assertions: []Assertion{}, Cleanup: []CleanupStep{{Type: "delete_created_entity", InterfaceID: "parent.create", OwnedReference: "created.parent"}},
		Safety:      Safety{Classification: "mutating", Mutating: true, RequiresOwnedData: true, CleanupRequired: true},
		EvidenceIDs: []string{}, GeneratedValues: []ValueReference{},
	}
	manifest := Manifest{SchemaVersion: SchemaVersion, RunnerVersion: RunnerVersion, PackID: "pack-1", Project: "Fixture",
		SourceRunID: "run-1", RuntimeRunID: "runtime-1", SourceCommit: "commit-1", CreatedAt: time.Unix(1, 0).UTC(),
		DefaultTarget: "https://example.test", TestIDs: []string{public.ID, mutation.ID, authenticated.ID}, TestCount: 3,
		Identities:     []IdentityReference{{ID: "admin", UsernameEnv: "FIXTURE_USERNAME", PasswordEnv: "FIXTURE_PASSWORD"}},
		Authentication: Authentication{LoginPath: "/login"}, Provenance: Provenance{Generator: "noescope"}}
	history := Execution{SchemaVersion: SchemaVersion, ExecutionID: "onboarding", PackID: "pack-1", Target: "https://example.test",
		StartedAt: time.Unix(2, 0).UTC(), CompletedAt: time.Unix(3, 0).UTC(), Results: []Result{
			{TestID: public.ID, Status: StatusPassed}, {TestID: authenticated.ID, Status: StatusPassed},
			{TestID: mutation.ID, Mutating: true, Status: StatusCleanupFailed,
				WorkflowFailure: "form <binding> failed", CleanupFailure: "cleanup confirmation failed", Reason: "workflow and cleanup failed"},
		}}
	history.SelectedIDs = manifest.TestIDs
	history.Summary = summarize(history.Results)
	return &Bundle{Manifest: manifest, Tests: []Test{public, mutation, authenticated}, History: []Execution{history}}
}

func writeFixtureBundle(t *testing.T, root string) *Bundle {
	t.Helper()
	bundle := portableFixture()
	bundle.Root = root
	if err := WriteJSON(filepath.Join(root, "testpack.json"), bundle.Manifest); err != nil {
		t.Fatal(err)
	}
	files := []string{"testpack.json"}
	for _, test := range bundle.Tests {
		relative := filepath.Join("tests", test.ID+".json")
		if err := WriteJSON(filepath.Join(root, relative), test); err != nil {
			t.Fatal(err)
		}
		files = append(files, filepath.ToSlash(relative))
	}
	if err := AtomicWrite(filepath.Join(root, "runner"), []byte("fixture-runner"), 0755); err != nil {
		t.Fatal(err)
	}
	files = append(files, "runner")
	if err := WriteJSON(filepath.Join(root, "runs", "onboarding", "execution.json"), bundle.History[0]); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(root, "runs", "onboarding", "evidence.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := BuildIntegrity(root, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(root, "testpack.lock.json"), lock); err != nil {
		t.Fatal(err)
	}
	return bundle
}

type portableFakeBrowser struct {
	mu          sync.Mutex
	events      []string
	loginResult *browser.Page
	submissions []browser.FormSubmission
}

func (f *portableFakeBrowser) Navigate(_ context.Context, target string) (browser.Page, error) {
	f.mu.Lock()
	f.events = append(f.events, "navigate:"+target)
	f.mu.Unlock()
	switch target {
	case "https://example.test/login", "https://override.test/login":
		return browser.Page{FinalURL: target, HTTPStatus: 200, Title: "Login", Forms: []browser.Form{{UsernameSelector: "#username", PasswordSelector: "#password", SubmitSelector: "#submit"}}}, nil
	case "https://example.test/dashboard", "https://override.test/dashboard":
		return browser.Page{FinalURL: target, HTTPStatus: 200, Title: "Dashboard"}, nil
	default:
		return browser.Page{}, errors.New("unexpected URL")
	}
}
func (f *portableFakeBrowser) SubmitLogin(_ context.Context, _ browser.LoginForm, credentials browser.Credentials) (browser.Page, error) {
	f.mu.Lock()
	f.events = append(f.events, "login")
	f.mu.Unlock()
	if f.loginResult != nil {
		return *f.loginResult, nil
	}
	return browser.Page{FinalURL: "https://example.test/", HTTPStatus: 200, Title: "Home", Cookies: []browser.Cookie{{Name: "session"}}}, nil
}
func (f *portableFakeBrowser) SubmitForm(_ context.Context, submission browser.FormSubmission) (browser.Page, error) {
	f.mu.Lock()
	f.submissions = append(f.submissions, submission)
	f.events = append(f.events, "totp")
	f.mu.Unlock()
	return browser.Page{FinalURL: "https://example.test/", HTTPStatus: 200, Title: "Home", Cookies: []browser.Cookie{{Name: "session"}}}, nil
}
func (f *portableFakeBrowser) Screenshot(context.Context, string) error { return nil }
func (f *portableFakeBrowser) Close() error                             { return nil }

func fakeFactory(fake *portableFakeBrowser) BrowserFactory {
	return func(context.Context, browser.Options) (browser.Engine, error) { return fake, nil }
}

func fixtureLookup(name string) (string, bool) {
	values := map[string]string{"FIXTURE_USERNAME": "sensitive-user", "FIXTURE_PASSWORD": "sensitive-password"}
	value, ok := values[name]
	return value, ok
}

func TestIntegrityDetectsCorruptDefinition(t *testing.T) {
	root := t.TempDir()
	writeFixtureBundle(t, root)
	path := filepath.Join(root, "tests", "auth.login.public.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("corrupt definition was accepted: %v", err)
	}
}

func TestRunnerListShowAndCopiedBundle(t *testing.T) {
	source := t.TempDir()
	writeFixtureBundle(t, source)
	destination := filepath.Join(t.TempDir(), "copied")
	copyTree(t, source, destination)
	var out, errOut bytes.Buffer
	if code := RunCLI(context.Background(), destination, []string{"list"}, &out, &errOut, nil); code != 0 {
		t.Fatalf("list failed: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "CLEANUP FAILED") || !strings.Contains(out.String(), "auth.login.public") {
		t.Fatal(out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := RunCLI(context.Background(), destination, []string{"show", "core.parent_child.lifecycle"}, &out, &errOut, nil); code != 0 {
		t.Fatal(errOut.String())
	}
	if !strings.Contains(out.String(), "Manual cleanup may be required") || !strings.Contains(out.String(), "cleanup confirmation failed") {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(filepath.Join(destination, "application.json")); !os.IsNotExist(err) {
		t.Fatal("copied bundle unexpectedly needs application.json")
	}
}

func TestRunnerSingleTestHistoryAndTargetOverride(t *testing.T) {
	root := t.TempDir()
	writeFixtureBundle(t, root)
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	fake := &portableFakeBrowser{}
	runner := Runner{Bundle: loaded, Options: RunOptions{SelectedTestID: "auth.login.public", BaseURL: "https://override.test", Headless: true,
		BrowserFactory: fakeFactory(fake), LookupEnv: fixtureLookup}}
	execution, executionRoot, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if execution.Summary.Passed != 1 || ExecutionExitCode(execution, true) != 0 {
		t.Fatalf("unexpected result: %#v", execution)
	}
	for _, name := range []string{"execution.json", "evidence.jsonl", "report.html", "report.md"} {
		if _, err := os.Stat(filepath.Join(executionRoot, name)); err != nil {
			t.Fatal(err)
		}
	}
	if len(loaded.History) != 1 {
		t.Fatal("Runner.Run should not overwrite in-memory historical source state")
	}
	reloaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.History) != 2 {
		t.Fatalf("new history was not preserved: %d", len(reloaded.History))
	}
	if !containsEvent(fake.events, "navigate:https://override.test/login") {
		t.Fatalf("target override not used: %#v", fake.events)
	}
}

func TestPortableRunnerTransparentlyCompletesTOTPWithoutPersistingSecrets(t *testing.T) {
	root := t.TempDir()
	writeFixtureBundle(t, root)
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Manifest.Identities[0].TOTP = &TOTPReference{SecretEnv: "NOESCOPE_TOTP_SECRET"}
	challenge := browser.Page{FinalURL: "https://example.test/two-factor", Title: "Two-factor authentication", Forms: []browser.Form{{
		Selector: "#totp", SubmitSelector: "#totp button", Controls: []browser.FormControl{{
			ID: "form-code", Name: "code", Type: "text", Label: "Authentication code", Autocomplete: "one-time-code", Selector: "#form-code",
		}},
	}}}
	fake := &portableFakeBrowser{loginResult: &challenge}
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	runner := Runner{Bundle: loaded, Options: RunOptions{SelectedTestID: "dashboard.show.authenticated", BrowserFactory: fakeFactory(fake),
		LookupEnv: func(name string) (string, bool) {
			values := map[string]string{"FIXTURE_USERNAME": "sensitive-user", "FIXTURE_PASSWORD": "sensitive-password", "NOESCOPE_TOTP_SECRET": seed}
			value, ok := values[name]
			return value, ok
		}}}
	execution, executionRoot, err := runner.Run(context.Background())
	if err != nil || execution.Summary.Passed != 1 || len(fake.submissions) != 1 || len(fake.submissions[0].Entries) != 1 {
		t.Fatalf("portable TOTP execution failed: %#v %#v %v", execution, fake.submissions, err)
	}
	code := fake.submissions[0].Entries[0].Value
	err = filepath.Walk(executionRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(raw), seed) || strings.Contains(string(raw), code) {
			t.Fatalf("portable artifact contains TOTP secret material: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPortableRunnerBlocksObservedTOTPWhenEnvironmentIsMissing(t *testing.T) {
	bundle := portableFixture()
	bundle.Root = t.TempDir()
	bundle.Manifest.Identities[0].TOTP = &TOTPReference{SecretEnv: "NOESCOPE_TOTP_SECRET"}
	challenge := browser.Page{FinalURL: "https://example.test/two-factor", Title: "Two-factor authentication", Forms: []browser.Form{{
		Selector: "#totp", SubmitSelector: "button", Controls: []browser.FormControl{{Name: "otp", Type: "text", Autocomplete: "one-time-code", Selector: "input[name=otp]"}},
	}}}
	fake := &portableFakeBrowser{loginResult: &challenge}
	runner := Runner{Bundle: bundle, Options: RunOptions{SelectedTestID: "dashboard.show.authenticated", BrowserFactory: fakeFactory(fake),
		LookupEnv: func(name string) (string, bool) {
			if name == "FIXTURE_USERNAME" {
				return "user", true
			}
			if name == "FIXTURE_PASSWORD" {
				return "password", true
			}
			return "", false
		}}}
	execution, _, err := runner.Run(context.Background())
	if err != nil || execution.Results[0].Status != StatusBlocked || !strings.Contains(execution.Results[0].Reason, "NOESCOPE_TOTP_SECRET") {
		t.Fatalf("missing portable TOTP seed was not blocked: %#v %v", execution, err)
	}
	for _, name := range []string{"report.html", "report.md"} {
		raw, readErr := os.ReadFile(filepath.Join(bundle.Root, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(raw), "NOESCOPE_TOTP_SECRET") || strings.Contains(string(raw), "otpauth://") {
			t.Fatalf("portable report did not safely render missing TOTP configuration: %s", name)
		}
	}
}

func TestRunnerAllExecutesReadOnlyAndIgnoresDisabledMutationForCI(t *testing.T) {
	t.Setenv("FIXTURE_USERNAME", "sensitive-user")
	t.Setenv("FIXTURE_PASSWORD", "sensitive-password")
	root := t.TempDir()
	writeFixtureBundle(t, root)
	var out, errOut bytes.Buffer
	code := RunCLI(context.Background(), root, []string{"test"}, &out, &errOut, fakeFactory(&portableFakeBrowser{}))
	if code != 0 {
		t.Fatalf("whole-pack read-only CI run failed: code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "BLOCKED") || !strings.Contains(out.String(), "core.parent_child.lifecycle") {
		t.Fatalf("disabled mutation was not reported: %s", out.String())
	}
	history, err := LoadHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	latest := history[len(history)-1]
	if latest.Summary.Passed != 2 || latest.Summary.Blocked != 1 || latest.Summary.Failed != 0 {
		t.Fatalf("unexpected whole-pack result: %#v", latest.Summary)
	}
}

func TestCIBlockedPolicy(t *testing.T) {
	mutation := &Execution{Results: []Result{{TestID: "mutation", Mutating: true, Status: StatusBlocked}, {TestID: "read", Status: StatusPassed}}}
	if ExecutionExitCode(mutation, false) != 0 || ExecutionExitCode(mutation, true) == 0 {
		t.Fatal("mutating blocked policy is wrong")
	}
	readBlocked := &Execution{Results: []Result{{TestID: "read", Status: StatusBlocked}}}
	if ExecutionExitCode(readBlocked, false) == 0 {
		t.Fatal("blocked read-only test should fail CI")
	}
	for _, status := range []string{StatusFailed, StatusCleanupFailed, StatusUnresolved} {
		if ExecutionExitCode(&Execution{Results: []Result{{Status: status}}}, false) == 0 {
			t.Fatalf("%s should fail CI", status)
		}
	}
}

func TestReportsEscapeHTMLAndRenderCleanupFailureWithoutSecrets(t *testing.T) {
	bundle := portableFixture()
	html, err := HTML(bundle)
	if err != nil {
		t.Fatal(err)
	}
	markdown := Markdown(bundle)
	for _, raw := range [][]byte{html, markdown} {
		text := string(raw)
		if strings.Contains(text, "sensitive-user") || strings.Contains(text, "sensitive-password") {
			t.Fatal("credentials rendered")
		}
		if !strings.Contains(text, "CLEANUP FAILED") || !strings.Contains(text, "Manual cleanup may be required") {
			t.Fatal(text)
		}
	}
	if strings.Contains(string(html), "Login <Public>") || !strings.Contains(string(html), "Login &lt;Public&gt;") {
		t.Fatal("HTML report did not escape test name")
	}
}

func TestWebUIReadOnlyRunAndMutatingConfirmation(t *testing.T) {
	bundle := portableFixture()
	bundle.Root = t.TempDir()
	fake := &portableFakeBrowser{}
	server := NewServer(bundle, RunOptions{Headless: true, Mutations: true, BrowserFactory: fakeFactory(fake), LookupEnv: fixtureLookup})
	handler := server.Handler()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Run All Eligible Tests") || !strings.Contains(response.Body.String(), "Run Test") {
		t.Fatal(response.Body.String())
	}
	form := url.Values{"ui_nonce": {server.nonce}, "test": {"core.parent_child.lifecycle"}}
	request = httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "This test modifies application data") || !strings.Contains(response.Body.String(), "Run Mutating Test") {
		t.Fatal(response.Body.String())
	}
	form = url.Values{"ui_nonce": {server.nonce}, "test": {"auth.login.public"}}
	request = httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("read-only UI run did not start: %d", response.Code)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		running := server.running
		server.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(time.Millisecond)
	}
	server.mu.Lock()
	history := len(server.bundle.History)
	server.mu.Unlock()
	if history != 2 {
		t.Fatalf("UI run did not append history: %d", history)
	}
}

func TestServerRejectsNonLoopbackBinding(t *testing.T) {
	server := NewServer(portableFixture(), RunOptions{})
	if err := server.Serve(context.Background(), "0.0.0.0:0"); err == nil {
		t.Fatal("non-loopback listener was accepted")
	}
}

func TestCredentialValuesAbsentFromExecutionArtifacts(t *testing.T) {
	root := t.TempDir()
	writeFixtureBundle(t, root)
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	runner := Runner{Bundle: loaded, Options: RunOptions{SelectedTestID: "dashboard.show.authenticated",
		BrowserFactory: fakeFactory(&portableFakeBrowser{}), LookupEnv: fixtureLookup}}
	_, executionRoot, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(executionRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range []string{"sensitive-user", "sensitive-password", "cookie-value", "bearer-token"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("secret %q in %s", secret, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(source, path)
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		_, err = io.Copy(output, input)
		closeErr := output.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
}

func containsEvent(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
