// Package authn implements deterministic, discovery-independent browser
// authentication helpers shared by runtime verification, Core Tests, and the
// portable runner.
package authn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

const (
	SecondFactorNotRequired = "not_required"
	SecondFactorRequired    = "required"
	SecondFactorVerified    = "verified"
	SecondFactorFailed      = "failed"
	SecondFactorBlocked     = "blocked"
	SecondFactorUnknown     = "unknown"
)

type TOTPReference struct {
	SecretEnv string
	Period    uint
	Digits    int
	Algorithm string
}

type Identity struct {
	Primary   browser.Credentials
	TOTP      *TOTPReference
	LookupEnv func(string) (string, bool)
}

type SecondFactorResult struct {
	Type      string
	Attempted bool
	Status    string
	Reason    string
}

type Result struct {
	Page         browser.Page
	SecondFactor SecondFactorResult
}

type Options struct {
	SourceSupportsTOTP bool
	Now                func() time.Time
	Sleep              func(context.Context, time.Duration) error
	BoundaryMargin     time.Duration
	RegisterSecrets    func(...string)
}

type TOTPChallenge struct {
	PageURL  string
	Form     browser.Form
	Field    browser.FormControl
	Selector string
}

// TOTPRequiredError means the application presented a confirmed TOTP
// challenge but the selected identity cannot supply its seed. It contains only
// an environment variable name, never secret material.
type TOTPRequiredError struct {
	EnvironmentName string
}

func (e *TOTPRequiredError) Error() string {
	if e.EnvironmentName == "" {
		return "authentication requires TOTP; identity totp.secret_env is not configured"
	}
	return fmt.Sprintf("authentication requires TOTP; environment variable %s is not configured", e.EnvironmentName)
}

type TOTPFailedError struct{ Reason string }

func (e *TOTPFailedError) Error() string {
	if e.Reason == "" {
		return "TOTP authentication failed"
	}
	return "TOTP authentication failed: " + e.Reason
}

func IsTOTPRequired(err error) bool {
	var target *TOTPRequiredError
	return errors.As(err, &target)
}

// CompleteSecondFactor inspects the page returned by primary authentication.
// It generates and submits TOTP only when that page is a deterministic TOTP
// challenge. Source support is a useful signal but is never treated as proof
// that this identity requires a second factor.
func CompleteSecondFactor(
	ctx context.Context,
	engine browser.Engine,
	page browser.Page,
	identity Identity,
	options Options,
) (Result, error) {
	result := Result{Page: page, SecondFactor: SecondFactorResult{Status: SecondFactorNotRequired}}
	challenge, ok := DetectTOTPChallenge(page, options.SourceSupportsTOTP)
	if !ok {
		return result, nil
	}
	result.SecondFactor = SecondFactorResult{Type: "totp", Status: SecondFactorRequired}
	if identity.TOTP == nil || strings.TrimSpace(identity.TOTP.SecretEnv) == "" {
		err := &TOTPRequiredError{}
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorBlocked, err.Error()
		return result, err
	}
	lookup := identity.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	secret, found := lookup(identity.TOTP.SecretEnv)
	if !found || strings.TrimSpace(secret) == "" {
		err := &TOTPRequiredError{EnvironmentName: identity.TOTP.SecretEnv}
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorBlocked, err.Error()
		return result, err
	}
	if options.RegisterSecrets != nil {
		options.RegisterSecrets(secret)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	period := normalizedPeriod(identity.TOTP.Period)
	margin := options.BoundaryMargin
	if margin == 0 {
		margin = 2 * time.Second
	}
	current := now()
	remaining := time.Duration(int64(period)-(current.Unix()%int64(period))) * time.Second
	if remaining <= margin {
		if err := sleep(ctx, remaining); err != nil {
			result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorFailed, "waiting for a fresh TOTP period was interrupted"
			return result, &TOTPFailedError{Reason: result.SecondFactor.Reason}
		}
		current = now()
	}
	code, err := GenerateCode(secret, current, *identity.TOTP)
	if err != nil {
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorFailed, "configured TOTP parameters or seed are invalid"
		return result, &TOTPFailedError{Reason: result.SecondFactor.Reason}
	}
	if options.RegisterSecrets != nil {
		options.RegisterSecrets(code)
	}
	submission := browser.FormSubmission{
		PageURL: challenge.PageURL, FormSelector: challenge.Form.Selector,
		SubmitSelector: challenge.Form.SubmitSelector,
		Entries:        []browser.FormEntry{{Selector: challenge.Selector, Type: challenge.Field.Type, Value: code}},
	}
	secondFactorEngine, supportsSecondFactor := engine.(browser.SecondFactorEngine)
	formSubmitter, supportsForm := engine.(browser.FormSubmitter)
	if !supportsSecondFactor && (!supportsForm || challenge.Form.SubmitSelector == "") {
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorUnknown, "browser does not support deterministic native TOTP form submission"
		return result, fmt.Errorf("%s", result.SecondFactor.Reason)
	}
	result.SecondFactor.Attempted = true
	var submitted browser.Page
	if supportsSecondFactor {
		submitted, err = secondFactorEngine.SubmitOneTimeCode(ctx, submission)
	} else {
		submitted, err = formSubmitter.SubmitForm(ctx, submission)
	}
	result.Page = submitted
	if err != nil {
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorFailed, "native TOTP form submission failed"
		return result, &TOTPFailedError{Reason: result.SecondFactor.Reason}
	}
	if _, remains := DetectTOTPChallenge(submitted, options.SourceSupportsTOTP); remains {
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorFailed, "the TOTP challenge remained after one submission"
		return result, &TOTPFailedError{Reason: result.SecondFactor.Reason}
	}
	if !authenticatedPageEvidence(submitted, challenge.PageURL) {
		result.SecondFactor.Status, result.SecondFactor.Reason = SecondFactorFailed, "authenticated state was not observed after TOTP submission"
		return result, &TOTPFailedError{Reason: result.SecondFactor.Reason}
	}
	result.SecondFactor.Status = SecondFactorVerified
	return result, nil
}

func authenticatedPageEvidence(page browser.Page, challengeURL string) bool {
	for _, element := range page.Elements {
		semantic := lowerSemantic(element.Name + " " + element.Text)
		if containsAny(semantic, "logout", "log out", "profile", "account") {
			return true
		}
	}
	// Cookie metadata is useful only in combination with successful navigation
	// away from the challenge. A cookie alone may be a pre-authentication session
	// and is never accepted as sole proof.
	semantic := lowerSemantic(page.Title)
	if len(page.Cookies) == 0 || sameLocation(page.FinalURL, challengeURL) ||
		page.HTTPStatus >= 400 || containsAny(semantic, "invalid code", "incorrect code", "authentication failed", "verification failed") {
		return false
	}
	return true
}

func sameLocation(left, right string) bool {
	l, leftErr := url.Parse(left)
	r, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return left == right
	}
	return l.Scheme == r.Scheme && l.Host == r.Host && strings.TrimRight(l.Path, "/") == strings.TrimRight(r.Path, "/") && l.RawQuery == r.RawQuery
}

func DetectTOTPChallenge(page browser.Page, sourceSupports bool) (TOTPChallenge, bool) {
	pageSemantics := lowerSemantic(page.Title)
	for _, element := range page.Elements {
		role := lowerSemantic(element.Role)
		if role == "heading" || role == "h1" || role == "h2" || role == "h3" {
			pageSemantics += " " + lowerSemantic(element.Name+" "+element.Text)
		}
	}
	negativePage := containsAny(pageSemantics, "password reset", "reset password", "email confirmation", "confirm email", "captcha", "sms code", "text message code", "email code", "push notification")
	bestScore := -1
	var best TOTPChallenge
	for _, form := range page.Forms {
		// A primary credential form is not a second-factor challenge.
		if form.PasswordSelector != "" {
			continue
		}
		formSemantics := lowerSemantic(form.Action + " " + form.SubmitLabel)
		for _, control := range form.Controls {
			switch strings.ToLower(control.Type) {
			case "", "text", "tel", "number":
			default:
				continue
			}
			semantics := lowerSemantic(control.ID + " " + control.Name + " " + control.Label + " " + control.Autocomplete)
			if containsAny(semantics+" "+formSemantics+" "+pageSemantics,
				"password reset", "reset password", "email confirmation", "confirm email", "captcha",
				"sms code", "text message code", "email code", "push notification") {
				continue
			}
			score := 0
			if strings.EqualFold(control.Autocomplete, "one-time-code") {
				score += 7
			}
			if hasTOTPTerm(control.ID) || hasTOTPTerm(control.Name) {
				score += 5
			}
			if hasStrongTOTPText(control.Label) {
				score += 5
			}
			if hasStrongTOTPText(form.Action) || hasStrongTOTPText(form.SubmitLabel) {
				score += 4
			}
			if hasStrongTOTPText(pageSemantics) {
				score += 3
			}
			if sourceSupports && lowerSemantic(control.Name) == "code" &&
				containsAny(formSemantics+" "+pageSemantics, "two factor", "second factor") {
				score += 5
			}
			if sourceSupports && score >= 4 {
				score++
			}
			if negativePage || score < 5 {
				continue
			}
			selector := stableFieldSelector(form, control)
			if selector == "" {
				continue
			}
			if score > bestScore {
				bestScore = score
				best = TOTPChallenge{PageURL: page.FinalURL, Form: form, Field: control, Selector: selector}
			}
		}
	}
	return best, bestScore >= 0
}

func stableFieldSelector(form browser.Form, control browser.FormControl) string {
	if strings.HasPrefix(control.Selector, "#") {
		return control.Selector
	}
	if form.Selector != "" && control.Selector != "" {
		return form.Selector + " " + control.Selector
	}
	return control.Selector
}

func hasTOTPTerm(value string) bool {
	value = lowerSemantic(value)
	for _, token := range []string{"otp", "totp", "one time", "one_time", "verification code", "verification_code", "authentication code", "authentication_code"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func hasStrongTOTPText(value string) bool {
	value = lowerSemantic(value)
	return containsAny(value, "totp", "one time code", "authenticator code", "authentication code", "two factor authentication", "two factor code")
}

func lowerSemantic(value string) string {
	value = strings.ToLower(value)
	value = strings.NewReplacer("-", " ", "_", " ", ":", " ", "/", " ", ".", " ").Replace(value)
	return strings.Join(strings.Fields(value), " ")
}

func containsAny(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func GenerateCode(secret string, at time.Time, reference TOTPReference) (string, error) {
	digits, err := otpDigits(reference.Digits)
	if err != nil {
		return "", err
	}
	algorithm, err := otpAlgorithm(reference.Algorithm)
	if err != nil {
		return "", err
	}
	return totp.GenerateCodeCustom(strings.TrimSpace(secret), at, totp.ValidateOpts{
		Period: normalizedPeriod(reference.Period), Digits: digits, Algorithm: algorithm,
	})
}

func normalizedPeriod(value uint) uint {
	if value == 0 {
		return 30
	}
	return value
}

func otpDigits(value int) (otp.Digits, error) {
	switch value {
	case 0, 6:
		return otp.DigitsSix, nil
	case 8:
		return otp.DigitsEight, nil
	default:
		return 0, fmt.Errorf("unsupported TOTP digits")
	}
}

func otpAlgorithm(value string) (otp.Algorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "SHA1":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported TOTP algorithm")
	}
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
