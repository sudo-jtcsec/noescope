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

	"github.com/sudo-jtcsec/noescope/internal/authn"
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

type totpRuntimeBrowser struct {
	fakeBrowser
	submissions []browser.FormSubmission
	reject      bool
}

func (f *totpRuntimeBrowser) SubmitLogin(_ context.Context, _ browser.LoginForm, credentials browser.Credentials) (browser.Page, error) {
	if credentials.Username != "alice" || credentials.Password != "super-secret" {
		return loginPage("https://app.example/login"), nil
	}
	return runtimeTOTPPage(), nil
}

func (f *totpRuntimeBrowser) SubmitForm(_ context.Context, submission browser.FormSubmission) (browser.Page, error) {
	f.submissions = append(f.submissions, submission)
	if f.reject {
		return runtimeTOTPPage(), nil
	}
	f.loggedIn = true
	return browser.Page{FinalURL: "https://app.example/dashboard", HTTPStatus: 200, Ready: true,
		Title: "Dashboard for alice", Elements: []browser.Element{{Role: "link", Text: "Logout"}},
		Cookies: []browser.Cookie{{Name: "session", HTTPOnly: true}}}, nil
}

func runtimeTOTPPage() browser.Page {
	return browser.Page{FinalURL: "https://app.example/two-factor", HTTPStatus: 200, Ready: true,
		Title: "Two-factor authentication", Forms: []browser.Form{{Selector: "#totp-form", Action: "/two-factor/check", Method: "POST",
			SubmitSelector: "#totp-form button[type=\"submit\"]", SubmitLabel: "Verify",
			Controls: []browser.FormControl{{ID: "form-code", Name: "code", Type: "text", Label: "Authentication code",
				Autocomplete: "one-time-code", Selector: "#form-code"}}}}}
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
	summary := Summarize(session.Runtime)
	if summary.SelectedInterfaces != 3 || summary.Observations != 4 {
		t.Fatalf("state observations changed unique selection accounting: %#v", summary)
	}
	for _, want := range []string{
		"[runtime] interfaces:", "selected=3", "observations=4",
		"verified=3", "auth_required=1", "contradicted=0",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("runtime telemetry missing %q: %s", want, logs.String())
		}
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

func TestVerifyAuthenticationCompletesObservedTOTPChallenge(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	redactor := NewRedactor("alice", "super-secret")
	fake := &totpRuntimeBrowser{fakeBrowser: fakeBrowser{loginWorks: true}}
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		TOTP: &authn.TOTPReference{SecretEnv: "FIXTURE_TOTP"}, LookupEnv: func(name string) (string, bool) { return seed, name == "FIXTURE_TOTP" },
		MaxInterfaces: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	authentication := session.Runtime.Authentication
	if authentication.Status != StatusVerified || authentication.PrimaryAuthentication != StatusVerified ||
		authentication.SecondFactor == nil || authentication.SecondFactor.Status != authn.SecondFactorVerified ||
		len(fake.submissions) != 1 || len(fake.submissions[0].Entries) != 1 {
		t.Fatalf("TOTP authentication was not verified: %#v submissions=%#v", authentication, fake.submissions)
	}
	code := fake.submissions[0].Entries[0].Value
	raw, err := json.Marshal(session.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), seed) || strings.Contains(string(raw), code) || strings.Contains(string(raw), "alice") {
		t.Fatalf("runtime model persisted authentication secret material: %s", raw)
	}
	if _, _, err := session.Write(); err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(session.Root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		artifact, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(artifact), seed) || strings.Contains(string(artifact), code) {
			t.Fatalf("runtime artifact contains TOTP secret material: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAuthenticationBlocksOnlyAfterObservedTOTPMissingSeed(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	redactor := NewRedactor("alice", "super-secret")
	fake := &totpRuntimeBrowser{fakeBrowser: fakeBrowser{loginWorks: true}}
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"}, MaxInterfaces: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Runtime.Authentication.Status != StatusBlocked ||
		!strings.Contains(session.Runtime.Authentication.Reason, "totp.secret_env") || len(fake.submissions) != 0 {
		t.Fatalf("missing TOTP reference was not safely blocked: %#v", session.Runtime.Authentication)
	}
}

func TestVerifyAuthenticationSeparatesPrimaryAndRejectedTOTP(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	redactor := NewRedactor("alice", "super-secret")
	fake := &totpRuntimeBrowser{fakeBrowser: fakeBrowser{loginWorks: true}, reject: true}
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		TOTP: &authn.TOTPReference{SecretEnv: "TOTP_SEED"}, LookupEnv: func(string) (string, bool) { return "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", true },
		MaxInterfaces: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := session.Runtime.Authentication
	if got.Status != StatusUnverified || got.PrimaryAuthentication != StatusVerified || got.SecondFactor == nil ||
		got.SecondFactor.Status != authn.SecondFactorFailed || len(fake.submissions) != 1 {
		t.Fatalf("primary and second factor failure were conflated: %#v", got)
	}
}

func TestPrimaryAuthenticationFailureNeverAttemptsTOTP(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	redactor := NewRedactor("wrong", "wrong")
	fake := &totpRuntimeBrowser{fakeBrowser: fakeBrowser{}}
	lookups := 0
	err = Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "wrong", Password: "wrong"},
		TOTP: &authn.TOTPReference{SecretEnv: "TOTP_SEED"}, LookupEnv: func(string) (string, bool) { lookups++; return "seed", true },
		MaxInterfaces: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Runtime.Authentication.Status != StatusUnverified || lookups != 0 || len(fake.submissions) != 0 {
		t.Fatalf("TOTP was attempted after primary failure: %#v lookups=%d", session.Runtime.Authentication, lookups)
	}
}

func TestInterfaceExpectationMatrixUsesKnownLoginSurface(t *testing.T) {
	public := &surface.Access{Authentication: "not_required"}
	required := &surface.Access{Authentication: "required"}
	loginURLs := []string{"https://app.example/login"}
	tests := []struct {
		name      string
		item      surface.Interface
		requested string
		page      browser.Page
		want      Status
	}{
		{
			name:      "public login route is the requested interface",
			item:      surface.Interface{ID: "session.entry", Type: "web_page", Access: public},
			requested: "https://app.example/login",
			page:      loginPage("https://app.example/login"),
			want:      StatusVerified,
		},
		{
			name:      "protected route redirected to login",
			item:      surface.Interface{ID: "dashboard", Type: "web_page", Access: required},
			requested: "https://app.example/dashboard",
			page:      loginPage("https://app.example/login"),
			want:      StatusAuthRequired,
		},
		{
			name:      "public route redirected to login",
			item:      surface.Interface{ID: "public.board", Type: "web_page", Access: public},
			requested: "https://app.example/public",
			page:      loginPage("https://app.example/login"),
			want:      StatusContradicted,
		},
		{
			name:      "protected route anonymously reachable",
			item:      surface.Interface{ID: "dashboard", Type: "web_page", Access: required},
			requested: "https://app.example/dashboard",
			page: browser.Page{
				RequestedURL: "https://app.example/dashboard",
				FinalURL:     "https://app.example/dashboard", HTTPStatus: 200, Ready: true,
			},
			want: StatusContradicted,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _ := classifyInterfacePage(
				test.item, "unauthenticated", test.requested, test.page, loginURLs,
			)
			if status != test.want {
				t.Fatalf("status = %q, want %q", status, test.want)
			}
		})
	}
}

func TestUnknownAccessAuthWallGetsAuthenticatedObservationWithinUniqueLimit(t *testing.T) {
	application := runtimeApplicationFixture()
	application.Surface.Interfaces = []surface.Interface{{
		ID: "user.list", Type: "web_page",
		Locator: surface.InterfaceLocator{Method: "GET", Path: "/admin"},
		Access:  &surface.Access{Authentication: "unknown"},
	}}
	application.Features = nil
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeBrowser{loginWorks: true}
	redactor := NewRedactor("alice", "super-secret")
	var logs strings.Builder
	if err := Verify(context.Background(), VerifyOptions{
		Application: application, Runtime: session.Runtime, RuntimeRoot: session.Root,
		Browser: fake, Evidence: NewEvidenceStore(session.Root, redactor), Redactor: redactor,
		IdentityID: "admin", Credentials: &browser.Credentials{Username: "alice", Password: "super-secret"},
		MaxInterfaces: 1,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(&logs, format+"\n", args...)
		},
	}); err != nil {
		t.Fatal(err)
	}
	byState := map[string]InterfaceObservation{}
	for _, observation := range session.Runtime.Interfaces {
		byState[observation.State] = observation
	}
	if byState["unauthenticated"].Status != StatusAuthRequired ||
		byState["authenticated"].Status != StatusVerified {
		t.Fatalf("unknown access auth wall was not retried after login: %#v", byState)
	}
	summary := Summarize(session.Runtime)
	if summary.SelectedInterfaces != 1 || summary.Observations != 2 ||
		!strings.Contains(logs.String(), "selected=1") ||
		!strings.Contains(logs.String(), "observations=2") {
		t.Fatalf("unique limit or telemetry counted states as interfaces: %#v\n%s", summary, logs.String())
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
