package authn

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

const vectorSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func challengePage() browser.Page {
	return browser.Page{FinalURL: "https://app.example/two-factor", Title: "Two-factor authentication", Forms: []browser.Form{{
		Selector: "form[action=\"/two-factor/check\"]", Action: "/two-factor/check", Method: "POST",
		SubmitSelector: "form[action=\"/two-factor/check\"] button[type=\"submit\"]", SubmitType: "submit", SubmitLabel: "Verify",
		Controls: []browser.FormControl{
			{ID: "csrf", Name: "csrf_token", Type: "hidden", Selector: "#csrf"},
			{ID: "form-code", Name: "code", Type: "text", Label: "Authentication code", Autocomplete: "one-time-code", Selector: "#form-code"},
			{Name: "remember_me", Type: "checkbox", Selector: "input[name=\"remember_me\"]"},
		},
	}}}
}

type factorBrowser struct {
	submissions []browser.FormSubmission
	result      browser.Page
	err         error
}

func (f *factorBrowser) Navigate(context.Context, string) (browser.Page, error) {
	return browser.Page{}, errors.New("unused")
}
func (f *factorBrowser) SubmitLogin(context.Context, browser.LoginForm, browser.Credentials) (browser.Page, error) {
	return browser.Page{}, errors.New("unused")
}
func (f *factorBrowser) SubmitForm(_ context.Context, submission browser.FormSubmission) (browser.Page, error) {
	f.submissions = append(f.submissions, submission)
	return f.result, f.err
}
func (f *factorBrowser) SubmitOneTimeCode(ctx context.Context, submission browser.FormSubmission) (browser.Page, error) {
	return f.SubmitForm(ctx, submission)
}
func (f *factorBrowser) Screenshot(context.Context, string) error { return nil }
func (f *factorBrowser) Close() error                             { return nil }

func TestDetectTOTPChallengeUsesStableSelectorAndIgnoresOtherControls(t *testing.T) {
	challenge, ok := DetectTOTPChallenge(challengePage(), false)
	if !ok {
		t.Fatal("TOTP challenge was not detected")
	}
	if challenge.Selector != "#form-code" || challenge.Field.Name != "code" {
		t.Fatalf("unexpected TOTP binding: %#v", challenge)
	}
}

func TestDetectTOTPChallengePrefersOneTimeCodeAutocomplete(t *testing.T) {
	page := challengePage()
	page.Forms[0].Controls = []browser.FormControl{
		{ID: "legacy-otp", Name: "otp", Type: "text", Selector: "#legacy-otp"},
		{ID: "preferred", Name: "code", Type: "text", Autocomplete: "one-time-code", Selector: "#preferred"},
	}
	challenge, ok := DetectTOTPChallenge(page, true)
	if !ok || challenge.Selector != "#preferred" {
		t.Fatalf("autocomplete one-time-code was not preferred: %#v", challenge)
	}
}

func TestDetectTOTPChallengeScopesNameSelectorToForm(t *testing.T) {
	page := challengePage()
	page.Forms[0].Selector = "#second-factor"
	page.Forms[0].Controls = []browser.FormControl{{Name: "authentication_code", Type: "text", Selector: `input[name="authentication_code"]`}}
	challenge, ok := DetectTOTPChallenge(page, false)
	if !ok || challenge.Selector != `#second-factor input[name="authentication_code"]` {
		t.Fatalf("name selector was not form-scoped: %#v", challenge)
	}
}

func TestSourceTOTPHintComplementsGenericTwoFactorCodeForm(t *testing.T) {
	page := browser.Page{FinalURL: "https://app.example/two-factor", Title: "Second factor", Forms: []browser.Form{{
		Selector: "form", Action: "/two-factor/check", SubmitSelector: "button",
		Controls: []browser.FormControl{{Name: "code", Type: "text", Selector: `input[name="code"]`}},
	}}}
	if _, ok := DetectTOTPChallenge(page, false); ok {
		t.Fatal("generic second-factor code was assumed to be TOTP without a source hint")
	}
	if _, ok := DetectTOTPChallenge(page, true); !ok {
		t.Fatal("source-backed TOTP support did not complement the observed second-factor form")
	}
}

func TestDetectTOTPChallengeRejectsIrrelevantCodesAndPasswordReset(t *testing.T) {
	for _, page := range []browser.Page{
		{FinalURL: "https://app.example/report", Forms: []browser.Form{{Selector: "form", SubmitSelector: "button", Controls: []browser.FormControl{{Name: "code", Type: "number", Selector: "input[name=code]"}}}}},
		{FinalURL: "https://app.example/reset", Title: "Password reset", Forms: []browser.Form{{Selector: "form", SubmitSelector: "button", Controls: []browser.FormControl{{Name: "otp", Type: "text", Autocomplete: "one-time-code", Selector: "input[name=otp]"}}}}},
		{FinalURL: "https://app.example/hidden", Forms: []browser.Form{{Selector: "form", SubmitSelector: "button", Controls: []browser.FormControl{{Name: "totp", Type: "hidden", Selector: "input[name=totp]"}}}}},
		{FinalURL: "https://app.example/sms", Title: "Enter SMS code", Forms: []browser.Form{{Selector: "form", SubmitSelector: "button", Controls: []browser.FormControl{{Name: "code", Type: "text", Autocomplete: "one-time-code", Selector: "input[name=code]"}}}}},
	} {
		if _, ok := DetectTOTPChallenge(page, true); ok {
			t.Fatalf("irrelevant code form was classified as TOTP: %#v", page)
		}
	}
}

func TestRFC6238SHA1Vectors(t *testing.T) {
	vectors := []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}}
	for _, vector := range vectors {
		got, err := GenerateCode(vectorSecret, time.Unix(vector.at, 0), TOTPReference{Period: 30, Digits: 8, Algorithm: "SHA1"})
		if err != nil || got != vector.want {
			t.Fatalf("vector %d: got %q, %v; want %q", vector.at, got, err, vector.want)
		}
	}
}

func TestRFC6238SHA256AndSHA512Vectors(t *testing.T) {
	vectors := []struct {
		algorithm string
		secret    string
		want      string
	}{
		{"SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====", "46119246"},
		{"SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=", "90693936"},
	}
	for _, vector := range vectors {
		got, err := GenerateCode(vector.secret, time.Unix(59, 0), TOTPReference{Period: 30, Digits: 8, Algorithm: vector.algorithm})
		if err != nil || got != vector.want {
			t.Fatalf("%s vector: got %q, %v; want %q", vector.algorithm, got, err, vector.want)
		}
	}
}

func TestCompleteSecondFactorWaitsAtBoundaryAndSubmitsOnlyOTP(t *testing.T) {
	fake := &factorBrowser{result: browser.Page{FinalURL: "https://app.example/dashboard", Title: "Dashboard", Cookies: []browser.Cookie{{Name: "session"}}}}
	times := []time.Time{time.Unix(29, 0), time.Unix(30, 0)}
	nowIndex := 0
	var slept time.Duration
	var protected []string
	result, err := CompleteSecondFactor(context.Background(), fake, challengePage(), Identity{
		TOTP:      &TOTPReference{SecretEnv: "TOTP_SEED", Period: 30, Digits: 8},
		LookupEnv: func(name string) (string, bool) { return vectorSecret, name == "TOTP_SEED" },
	}, Options{
		Now: func() time.Time {
			value := times[nowIndex]
			if nowIndex < len(times)-1 {
				nowIndex++
			}
			return value
		},
		Sleep:           func(_ context.Context, duration time.Duration) error { slept = duration; return nil },
		RegisterSecrets: func(values ...string) { protected = append(protected, values...) },
	})
	if err != nil || result.SecondFactor.Status != SecondFactorVerified || slept != time.Second {
		t.Fatalf("unexpected completion: %#v sleep=%v err=%v", result, slept, err)
	}
	if len(fake.submissions) != 1 || len(fake.submissions[0].Entries) != 1 || fake.submissions[0].Entries[0].Selector != "#form-code" {
		t.Fatalf("submission modified controls other than the OTP field: %#v", fake.submissions)
	}
	if !reflect.DeepEqual(protected[:1], []string{vectorSecret}) || len(protected) != 2 || protected[1] == "" {
		t.Fatalf("seed/code were not registered for redaction: %#v", protected)
	}
}

func TestTOTPChallengeWithoutSubmitUsesSecondFactorEngineFallback(t *testing.T) {
	page := challengePage()
	page.Forms[0].SubmitSelector = ""
	fake := &factorBrowser{result: browser.Page{FinalURL: "https://app.example/dashboard", Cookies: []browser.Cookie{{Name: "session"}}}}
	result, err := CompleteSecondFactor(context.Background(), fake, page, Identity{
		TOTP: &TOTPReference{SecretEnv: "SEED"}, LookupEnv: func(string) (string, bool) { return vectorSecret, true },
	}, Options{Now: func() time.Time { return time.Unix(60, 0) }})
	if err != nil || result.SecondFactor.Status != SecondFactorVerified || len(fake.submissions) != 1 {
		t.Fatalf("Enter fallback path was not accepted: %#v %v", result, err)
	}
}

func TestCompleteSecondFactorIsLazyAndReportsMissingSecretReference(t *testing.T) {
	fake := &factorBrowser{}
	lookups := 0
	result, err := CompleteSecondFactor(context.Background(), fake, browser.Page{FinalURL: "https://app.example/dashboard"}, Identity{
		TOTP: &TOTPReference{SecretEnv: "TOTP_SEED"}, LookupEnv: func(string) (string, bool) { lookups++; return vectorSecret, true },
	}, Options{SourceSupportsTOTP: true})
	if err != nil || result.SecondFactor.Status != SecondFactorNotRequired {
		t.Fatalf("identity without a challenge changed: %#v %v", result, err)
	}
	if lookups != 0 {
		t.Fatal("source TOTP support caused eager secret resolution")
	}
	_, err = CompleteSecondFactor(context.Background(), fake, challengePage(), Identity{}, Options{})
	if !IsTOTPRequired(err) || !strings.Contains(err.Error(), "totp.secret_env") {
		t.Fatalf("missing reference was not reported safely: %v", err)
	}
	_, err = CompleteSecondFactor(context.Background(), fake, challengePage(), Identity{
		TOTP: &TOTPReference{SecretEnv: "NOESCOPE_TOTP_SECRET"}, LookupEnv: func(string) (string, bool) { return "", false },
	}, Options{})
	if !IsTOTPRequired(err) || !strings.Contains(err.Error(), "NOESCOPE_TOTP_SECRET") {
		t.Fatalf("missing environment variable was not named safely: %v", err)
	}
}

func TestRejectedTOTPIsBoundedAndNeverAppearsInError(t *testing.T) {
	fake := &factorBrowser{result: challengePage()}
	var generated string
	_, err := CompleteSecondFactor(context.Background(), fake, challengePage(), Identity{
		TOTP: &TOTPReference{SecretEnv: "SEED"}, LookupEnv: func(string) (string, bool) { return vectorSecret, true },
	}, Options{Now: func() time.Time { return time.Unix(60, 0) }, RegisterSecrets: func(values ...string) { generated = values[len(values)-1] }})
	if err == nil || len(fake.submissions) != 1 || generated == "" || strings.Contains(err.Error(), generated) || strings.Contains(err.Error(), vectorSecret) {
		t.Fatalf("rejected TOTP was unsafe or retried: submissions=%d error=%v", len(fake.submissions), err)
	}
}
