package portabletests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/authn"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

type BrowserFactory func(context.Context, browser.Options) (browser.Engine, error)

type RunOptions struct {
	BaseURL        string
	Headless       bool
	ExecutablePath string
	Mutations      bool
	SelectedTestID string
	OutputRoot     string
	BrowserFactory BrowserFactory
	LookupEnv      func(string) (string, bool)
}

type Runner struct {
	Bundle   *Bundle
	Options  RunOptions
	evidence []Evidence
	secrets  []string
}

func (r *Runner) Run(ctx context.Context) (*Execution, string, error) {
	if r.Bundle == nil {
		return nil, "", fmt.Errorf("portable test bundle is unavailable")
	}
	baseURL := strings.TrimSpace(r.Options.BaseURL)
	if baseURL == "" {
		baseURL = r.Bundle.Manifest.DefaultTarget
	}
	if _, err := parseBaseURL(baseURL); err != nil {
		return nil, "", err
	}
	tests := r.Bundle.Tests
	if r.Options.SelectedTestID != "" {
		selected, ok := findTest(tests, r.Options.SelectedTestID)
		if !ok {
			return nil, "", fmt.Errorf("test %q was not found", r.Options.SelectedTestID)
		}
		tests = []Test{selected}
	}
	executionID := "execution_" + newSuffix()
	execution := &Execution{
		SchemaVersion: SchemaVersion, ExecutionID: executionID, PackID: r.Bundle.Manifest.PackID,
		Target: sanitizeURL(baseURL), StartedAt: time.Now().UTC(), Results: []Result{},
	}
	r.evidence = []Evidence{}
	r.secrets = nil
	for _, test := range tests {
		execution.SelectedIDs = append(execution.SelectedIDs, test.ID)
		result := r.runTest(ctx, executionID, baseURL, test)
		execution.Results = append(execution.Results, result)
	}
	execution.CompletedAt = time.Now().UTC()
	execution.Summary = summarize(execution.Results)
	root := r.Options.OutputRoot
	if root == "" {
		root = filepath.Join(r.Bundle.Root, "runs")
	}
	executionRoot := filepath.Join(root, executionID)
	if err := WriteJSON(filepath.Join(executionRoot, "execution.json"), execution); err != nil {
		return execution, executionRoot, err
	}
	if err := writeEvidence(filepath.Join(executionRoot, "evidence.jsonl"), r.evidence); err != nil {
		return execution, executionRoot, err
	}
	updated := *r.Bundle
	updated.History = append(append([]Execution(nil), r.Bundle.History...), *execution)
	updated.Evidence = append(append([]Evidence(nil), r.Bundle.Evidence...), r.evidence...)
	if err := WriteReports(executionRoot, &updated); err != nil {
		return execution, executionRoot, err
	}
	if err := WriteReports(r.Bundle.Root, &updated); err != nil {
		return execution, executionRoot, err
	}
	return execution, executionRoot, nil
}

func (r *Runner) runTest(ctx context.Context, executionID, baseURL string, test Test) (result Result) {
	started := time.Now()
	result = Result{TestID: test.ID, Mutating: test.Safety.Mutating, Status: StatusUnresolved, EvidenceIDs: []string{}, OwnedObjects: []OwnedObject{}}
	defer func() { result.DurationMS = time.Since(started).Milliseconds() }()
	if test.Safety.Mutating && !r.Options.Mutations {
		result.Status = StatusBlocked
		result.Reason = "portable runner mutations are disabled"
		result.EvidenceIDs = append(result.EvidenceIDs, r.addEvidence(test.ID, "test_execution", "", result.Reason, ""))
		return result
	}
	identity, credentials, credentialErr := r.resolveCredentials(test)
	if credentialErr != nil && test.Preconditions.Authentication == "authenticated" {
		result.Status = StatusBlocked
		result.Reason = credentialErr.Error()
		return result
	}
	factory := r.Options.BrowserFactory
	if factory == nil {
		factory = func(ctx context.Context, options browser.Options) (browser.Engine, error) {
			return browser.NewChrome(ctx, options)
		}
	}
	engine, err := factory(ctx, browser.Options{Headless: r.Options.Headless, ExecutablePath: r.Options.ExecutablePath})
	if err != nil {
		result.Status, result.Reason = StatusFailed, r.sanitize("start browser: "+err.Error(), credentials)
		return result
	}
	defer engine.Close()
	page := browser.Page{}
	authenticated := false
	if test.Preconditions.Authentication == "authenticated" {
		page, err = r.authenticate(ctx, engine, baseURL, identity, credentials)
		if err != nil {
			result.Status, result.Reason = StatusFailed, r.sanitize(err.Error(), credentials)
			if authn.IsTOTPRequired(err) {
				result.Status = StatusBlocked
			}
			return result
		}
		authenticated = true
		result.EvidenceIDs = append(result.EvidenceIDs, r.addEvidence(test.ID, "test_step", "", "Authenticated test identity", page.FinalURL))
	}
	if test.Safety.Mutating {
		mutationEngine, ok := engine.(browser.MutationEngine)
		if !ok {
			result.Status, result.Reason = StatusUnresolved, "browser does not support bounded form mutation"
			return result
		}
		result = r.runMutating(ctx, executionID, baseURL, test, mutationEngine, page, identity, credentials)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	for _, step := range test.Steps {
		switch step.Type {
		case "navigate":
			item, ok := portableInterface(test, step.InterfaceID)
			if !ok {
				result.Status, result.Reason = StatusUnresolved, "test lacks an interface execution binding"
				return result
			}
			target, routeErr := resolveURL(baseURL, item.Path, nil)
			if routeErr != nil {
				result.Status, result.Reason = StatusUnresolved, routeErr.Error()
				return result
			}
			page, err = engine.Navigate(ctx, target)
			if err != nil {
				result.Status, result.Reason = StatusFailed, r.sanitize("navigate: "+err.Error(), credentials)
				return result
			}
			result.EvidenceIDs = append(result.EvidenceIDs, r.addEvidence(test.ID, "test_step", step.InterfaceID, "Navigated to portable interface", page.FinalURL))
		case "observe":
		default:
			result.Status, result.Reason = StatusUnresolved, fmt.Sprintf("portable read-only executor does not support step %q", step.Type)
			return result
		}
	}
	for _, assertion := range test.Assertions {
		if err := evaluate(assertion, page, authenticated, baseURL, r.Bundle.Manifest.DefaultTarget); err != nil {
			result.Status, result.Reason = StatusFailed, r.sanitize(err.Error(), credentials)
			return result
		}
		result.EvidenceIDs = append(result.EvidenceIDs, r.addEvidence(test.ID, "test_assertion", assertion.InterfaceID, "Assertion passed: "+assertion.Type, page.FinalURL))
	}
	result.Status = StatusPassed
	return result
}

func (r *Runner) addEvidence(testID, kind, interfaceID, description, target string) string {
	id := "evidence_" + newSuffix()
	r.evidence = append(r.evidence, Evidence{ID: id, Type: kind, TestID: testID,
		InterfaceID: interfaceID, Description: r.sanitize(description, browser.Credentials{}),
		URL: sanitizeURL(r.sanitize(target, browser.Credentials{})), CreatedAt: time.Now().UTC()})
	return id
}

func (r *Runner) authenticate(ctx context.Context, engine browser.Engine, baseURL string, identity IdentityReference, credentials browser.Credentials) (browser.Page, error) {
	loginURL, err := resolveURL(baseURL, r.Bundle.Manifest.Authentication.LoginPath, nil)
	if err != nil {
		return browser.Page{}, err
	}
	page, err := engine.Navigate(ctx, loginURL)
	if err != nil {
		return page, fmt.Errorf("navigate to login surface: %w", err)
	}
	login, ok := browser.DetectLoginForm(page)
	if !ok {
		return page, fmt.Errorf("login surface has no deterministic login form")
	}
	page, err = engine.SubmitLogin(ctx, login, credentials)
	if err != nil {
		return page, fmt.Errorf("submit login: %w", err)
	}
	var totpReference *authn.TOTPReference
	if identity.TOTP != nil {
		totpReference = &authn.TOTPReference{SecretEnv: identity.TOTP.SecretEnv,
			Period: identity.TOTP.Period, Digits: identity.TOTP.Digits, Algorithm: identity.TOTP.Algorithm}
	}
	completed, secondErr := authn.CompleteSecondFactor(ctx, engine, page, authn.Identity{
		Primary: credentials, TOTP: totpReference, LookupEnv: r.lookupEnv,
	}, authn.Options{SourceSupportsTOTP: identity.TOTP != nil, RegisterSecrets: r.registerSecrets})
	page = completed.Page
	if secondErr != nil {
		return page, secondErr
	}
	if _, stillLogin := browser.DetectLoginForm(page); stillLogin {
		return page, fmt.Errorf("authentication failed: login form remained")
	}
	return page, nil
}

func (r *Runner) lookupEnv(name string) (string, bool) {
	lookup := r.Options.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	return lookup(name)
}

func (r *Runner) registerSecrets(values ...string) {
	for _, value := range values {
		if value != "" {
			r.secrets = append(r.secrets, value)
		}
	}
}

func (r *Runner) sanitize(value string, credentials browser.Credentials) string {
	secrets := append(credentialSecrets(credentials), r.secrets...)
	return sanitizeText(value, secrets...)
}

func (r *Runner) resolveCredentials(test Test) (IdentityReference, browser.Credentials, error) {
	identityID := test.Identity
	if identityID == "" {
		identityID = firstIdentity(r.Bundle.Manifest.Identities)
	}
	for _, identity := range r.Bundle.Manifest.Identities {
		if identity.ID != identityID {
			continue
		}
		lookup := r.Options.LookupEnv
		if lookup == nil {
			lookup = os.LookupEnv
		}
		username, usernameOK := lookup(identity.UsernameEnv)
		password, passwordOK := lookup(identity.PasswordEnv)
		if !usernameOK || username == "" || !passwordOK || password == "" {
			return identity, browser.Credentials{}, fmt.Errorf("identity %q credential environment references are unavailable", identity.ID)
		}
		return identity, browser.Credentials{Username: username, Password: password}, nil
	}
	return IdentityReference{}, browser.Credentials{}, fmt.Errorf("identity %q is not defined by this bundle", identityID)
}

func findTest(tests []Test, id string) (Test, bool) {
	for _, test := range tests {
		if test.ID == id {
			return test, true
		}
	}
	return Test{}, false
}

func portableInterface(test Test, id string) (Interface, bool) {
	for _, item := range test.Interfaces {
		if item.ID == id {
			return item, true
		}
	}
	return Interface{}, false
}

func evaluate(assertion Assertion, page browser.Page, authenticated bool, baseURL, originalBase string) error {
	switch assertion.Type {
	case "http_status":
		if page.HTTPStatus != assertion.HTTPStatus {
			return fmt.Errorf("HTTP status is %d, expected %d", page.HTTPStatus, assertion.HTTPStatus)
		}
	case "page_title":
		match := assertion.Match
		if match == "" {
			match = "exact"
		}
		matched := match == "exact" && page.Title == assertion.Expected ||
			match == "prefix" && strings.HasPrefix(page.Title, assertion.Expected) ||
			match == "contains" && strings.Contains(page.Title, assertion.Expected)
		if !matched {
			return fmt.Errorf("page title did not match expected %s %q", match, assertion.Expected)
		}
	case "url_matches":
		expected := rebaseURL(assertion.Expected, originalBase, baseURL)
		if !sameURL(page.FinalURL, expected) {
			return fmt.Errorf("final URL does not match expected URL")
		}
	case "authenticated":
		if !authenticated || hasLoginForm(page) {
			return fmt.Errorf("browser is not authenticated")
		}
	case "not_authenticated":
		if !hasLoginForm(page) {
			return fmt.Errorf("login surface was not observed")
		}
	case "element_present", "text_present", "entity_visible":
		if !pageContains(page, assertion.Expected) {
			return fmt.Errorf("page does not contain expected semantic value")
		}
	default:
		return fmt.Errorf("unsupported assertion %q", assertion.Type)
	}
	return nil
}

func summarize(results []Result) Summary {
	summary := Summary{Total: len(results)}
	for _, result := range results {
		switch result.Status {
		case StatusPassed:
			summary.Passed++
		case StatusFailed:
			summary.Failed++
		case StatusBlocked:
			summary.Blocked++
		case StatusCleanupFailed:
			summary.CleanupFailed++
		case StatusUnresolved:
			summary.Unresolved++
		default:
			summary.NotRun++
		}
	}
	return summary
}

func parseBaseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("base URL must be an absolute HTTP(S) URL")
	}
	parsed.RawQuery, parsed.Fragment, parsed.User = "", "", nil
	return parsed, nil
}

func resolveURL(baseURL, path string, bindings map[string]string) (string, error) {
	for _, parameter := range routeParameters(path) {
		value := bindings[parameter]
		if value == "" {
			return "", fmt.Errorf("route %q requires runtime binding %q", path, parameter)
		}
		path = strings.ReplaceAll(path, "{"+parameter+"}", url.PathEscape(value))
	}
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(reference)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "", fmt.Errorf("interface path resolves outside configured target")
	}
	return resolved.String(), nil
}

func rebaseURL(expected, oldBase, newBase string) string {
	want, wantErr := url.Parse(expected)
	old, oldErr := url.Parse(oldBase)
	base, baseErr := parseBaseURL(newBase)
	if wantErr != nil || oldErr != nil || baseErr != nil || want.Host != old.Host {
		return expected
	}
	want.Scheme, want.Host, want.User = base.Scheme, base.Host, nil
	return want.String()
}

func sameURL(left, right string) bool {
	l, lerr := url.Parse(left)
	r, rerr := url.Parse(right)
	return lerr == nil && rerr == nil && l.Scheme == r.Scheme && l.Host == r.Host &&
		strings.TrimSuffix(l.Path, "/") == strings.TrimSuffix(r.Path, "/") && l.RawQuery == r.RawQuery
}

func pageContains(page browser.Page, expected string) bool {
	expected = strings.ToLower(expected)
	for _, element := range page.Elements {
		if strings.Contains(strings.ToLower(element.Role+" "+element.Name+" "+element.Text), expected) {
			return true
		}
	}
	for _, link := range page.Links {
		if strings.Contains(strings.ToLower(link.Text), expected) {
			return true
		}
	}
	return false
}

func hasLoginForm(page browser.Page) bool {
	_, ok := browser.DetectLoginForm(page)
	return ok
}

func firstIdentity(values []IdentityReference) string {
	if len(values) == 0 {
		return ""
	}
	return values[0].ID
}

func credentialSecrets(credentials browser.Credentials) []string {
	return []string{credentials.Username, credentials.Password}
}

func sanitizeText(value string, secrets ...string) string {
	value = redactOTPAuth(value)
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}

func redactOTPAuth(value string) string {
	for {
		lower := strings.ToLower(value)
		start := strings.Index(lower, "otpauth://")
		if start < 0 {
			return value
		}
		end := len(value)
		for index := start; index < len(value); index++ {
			if strings.ContainsRune(" \t\r\n\"'<>]", rune(value[index])) {
				end = index
				break
			}
		}
		value = value[:start] + "[REDACTED]" + value[end:]
	}
}

func sanitizeURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "key") || strings.Contains(lower, "auth") || strings.Contains(lower, "otp") {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func newSuffix() string {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool { return results[i].TestID < results[j].TestID })
}
