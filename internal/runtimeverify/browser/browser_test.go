package browser

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const loginFormRegressionFixture = `<form method="post" action="/login/check">
  <input type="hidden" name="csrf_token" value="SECRET">
  <input type="text" name="username" id="form-username" autocomplete="username">
  <input type="password" name="password" id="form-password" autocomplete="current-password">
  <input type="checkbox" name="remember_me" value="1" checked>
  <button type="submit">Sign in</button>
</form>`

func TestDetectLoginForm(t *testing.T) {
	page := Page{FinalURL: "https://example.test/login", Forms: []Form{
		{Action: "/search", UsernameSelector: "input[name=q]"},
		{Action: "/login", UsernameSelector: "#username", PasswordSelector: "#password", SubmitSelector: "button"},
	}}
	login, ok := DetectLoginForm(page)
	if !ok || login.PageURL != page.FinalURL || login.Form.Action != "/login" {
		t.Fatalf("login form not detected: %#v, %v", login, ok)
	}
}

func TestPageAndLoginFormContainNoInputValues(t *testing.T) {
	// The browser observation model intentionally has metadata but no field for
	// input values, response bodies, or cookie values.
	form := Form{UsernameField: "username", PasswordField: "password"}
	if form.UsernameField == "" || form.PasswordField == "" {
		t.Fatal("form metadata missing")
	}
	if _, ok := reflect.TypeOf(Cookie{}).FieldByName("Value"); ok {
		t.Fatal("cookie observation model must not retain cookie values")
	}
}

func TestLoginFormRegressionFixtureUsesStableSelectorsAndIgnoresOtherControls(t *testing.T) {
	if !strings.Contains(loginFormRegressionFixture, `name="csrf_token" value="SECRET"`) {
		t.Fatal("regression fixture does not contain a changing CSRF value")
	}
	forms := formsFromSnapshot([]formSnapshot{{
		Action: "/login/check", Method: "POST",
		Controls: []controlSnapshot{
			{Name: "csrf_token", Type: "hidden", Selector: `input[name="csrf_token"]`},
			{Name: "username", ID: "form-username", Type: "text", Autocomplete: "username", Selector: "#form-username"},
			{Name: "password", ID: "form-password", Type: "password", Autocomplete: "current-password", Selector: "#form-password"},
			{Name: "remember_me", Type: "checkbox", Selector: `input[name="remember_me"]`},
		},
		Submit: &controlSnapshot{
			Type: "submit", Text: "Sign in",
			Selector: `form[action="/login/check"] button[type="submit"]`,
		},
	}})
	if len(forms) != 1 {
		t.Fatalf("expected one discovered form, got %#v", forms)
	}
	form := forms[0]
	if form.UsernameSelector != "#form-username" || form.PasswordSelector != "#form-password" ||
		form.SubmitSelector != `form[action="/login/check"] button[type="submit"]` {
		t.Fatalf("unstable login selectors: %#v", form)
	}
	if form.UsernameField != "username" || form.PasswordField != "password" ||
		form.UsernameAutocomplete != "username" || form.PasswordAutocomplete != "current-password" {
		t.Fatalf("safe control metadata missing: %#v", form)
	}
	raw, err := json.Marshal(form)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"SECRET", "csrf_token", "remember_me", `"value"`, `"checked"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("discovered form persisted ignored field data %q: %s", forbidden, raw)
		}
	}
	plan := newLoginSubmissionPlan(form)
	if plan.UsernameSelector != "#form-username" || plan.PasswordSelector != "#form-password" ||
		plan.SubmitSelector != `form[action="/login/check"] button[type="submit"]` {
		t.Fatalf("submission did not retain stable live selectors: %#v", plan)
	}
	if _, ok := reflect.TypeOf(plan).FieldByName("NodeID"); ok {
		t.Fatal("submission plan must not retain Chrome DOM NodeIDs")
	}
	if actions := loginSubmissionActions(plan, Credentials{
		Username: "fixture-user", Password: "fixture-password",
	}); len(actions) != 11 {
		t.Fatalf("submission should touch two controls and one submit button, got %d actions", len(actions))
	}
}

func TestMutationFormObservationRetainsOnlySafeMetadata(t *testing.T) {
	forms := formsFromSnapshot([]formSnapshot{{
		Selector: "#create", Action: "/project/save?csrf_token=SECRET", Method: "POST",
		Controls: []controlSnapshot{
			{Name: "csrf_token", Type: "hidden", Selector: `input[name="csrf_token"]`},
			{Name: "name", ID: "form-name", Type: "text", Label: "Name", Selector: "#form-name"},
			{Name: "remember", Type: "checkbox", Selector: `input[name="remember"]`},
			{Name: "description", Type: "textarea", Label: "Description", Selector: "#description"},
		},
		Submit: &controlSnapshot{Type: "submit", Text: "Save", Selector: "#create button[type=submit]"},
	}})
	if len(forms) != 1 || len(forms[0].Controls) != 2 {
		t.Fatalf("unsafe mutation controls were retained: %#v", forms)
	}
	if forms[0].Controls[0].Name != "name" || forms[0].Controls[1].Name != "description" {
		t.Fatalf("safe semantic controls missing: %#v", forms[0].Controls)
	}
	raw, err := json.Marshal(forms[0].Controls)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"SECRET", "csrf_token", "remember", `"value"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("unsafe form state persisted %q: %s", forbidden, raw)
		}
	}
}
