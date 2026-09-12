package coretests

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/authn"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type BrowserFactory func(context.Context) (browser.Engine, error)

type ExecutorOptions struct {
	Application                     *model.Application
	Runtime                         *runtimeverify.Runtime
	Credentials                     *browser.Credentials
	TOTP                            *authn.TOTPReference
	LookupEnv                       func(string) (string, bool)
	RegisterSecrets                 func(...string)
	AuthenticationUnavailableReason string
	MutationsEnabled                bool
	Cleanup                         string
	BrowserFactory                  BrowserFactory
	Evidence                        *EvidenceStore
}

func ExecuteCandidates(
	ctx context.Context,
	candidates []testsmodel.TestCase,
	options ExecutorOptions,
) []testsmodel.CandidateResult {
	results := make([]testsmodel.CandidateResult, 0, len(candidates))
	for _, candidate := range candidates {
		results = append(results, executeCandidate(ctx, candidate, options))
	}
	return results
}

func executeCandidate(
	ctx context.Context,
	candidate testsmodel.TestCase,
	options ExecutorOptions,
) testsmodel.CandidateResult {
	result := testsmodel.CandidateResult{
		Candidate: candidate, Status: testsmodel.StatusCandidate,
		EvidenceIDs: []string{}, Values: map[string]string{},
	}
	addEvidence := func(kind, interfaceID, summary, target string, attributes map[string]string) {
		if options.Evidence == nil {
			return
		}
		record, err := options.Evidence.Add(EvidenceRecord{
			Kind: kind, TestID: candidate.ID, InterfaceID: interfaceID,
			Summary: summary, URL: target, Attributes: attributes,
		})
		if err == nil {
			result.EvidenceIDs = append(result.EvidenceIDs, record.ID)
		}
	}
	if err := testsmodel.ValidateTest(candidate, options.Application); err != nil {
		result.Status = testsmodel.StatusUnresolved
		result.Reason = err.Error()
		addEvidence("test_execution", "", "Candidate validation failed: "+err.Error(), "", nil)
		return result
	}
	if candidate.Safety.Mutating && !options.MutationsEnabled {
		result.Status = testsmodel.StatusBlocked
		result.Reason = "testing.mutations.enabled=false"
		addEvidence("test_execution", "", "Mutation candidate was blocked by testing configuration", "", nil)
		return result
	}
	if candidate.Preconditions.Authentication == "authenticated" && options.Credentials == nil {
		result.Status = testsmodel.StatusBlocked
		result.Reason = options.AuthenticationUnavailableReason
		if result.Reason == "" {
			result.Reason = "configured testing identity credentials are unavailable"
		}
		addEvidence("test_execution", "", "Authenticated candidate was blocked: "+result.Reason, "", nil)
		return result
	}
	if candidate.Safety.Mutating {
		result.Status = testsmodel.StatusUnresolved
		result.Reason = "mutating candidate lacks a proven owned-object creation binding"
		addEvidence("test_execution", "", result.Reason, "", nil)
		return result
	}
	if options.BrowserFactory == nil {
		result.Status = testsmodel.StatusUnresolved
		result.Reason = "browser factory is unavailable"
		return result
	}
	engine, err := options.BrowserFactory(ctx)
	if err != nil {
		result.Status = testsmodel.StatusFailed
		result.Reason = "start browser: " + err.Error()
		addEvidence("test_execution", "", result.Reason, "", nil)
		return result
	}
	defer engine.Close()

	authenticated := false
	var page browser.Page
	if candidate.Preconditions.Authentication == "authenticated" {
		page, err = authenticate(ctx, engine, options)
		if err != nil {
			result.Status = testsmodel.StatusFailed
			if authn.IsTOTPRequired(err) {
				result.Status = testsmodel.StatusBlocked
			}
			result.Reason = err.Error()
			addEvidence("test_execution", "", "Authentication precondition failed: "+err.Error(), "", nil)
			return result
		}
		authenticated = true
		addEvidence("test_step", "", "Established authenticated precondition", page.FinalURL, nil)
	}
	interfaces := make(map[string]surface.Interface, len(options.Application.Surface.Interfaces))
	for _, item := range options.Application.Surface.Interfaces {
		interfaces[item.ID] = item
	}
	for index, step := range candidate.Steps {
		switch step.Type {
		case "navigate":
			item, ok := interfaces[step.InterfaceID]
			if !ok {
				result.Status = testsmodel.StatusUnresolved
				result.Reason = fmt.Sprintf("step %d references unknown interface", index)
				return result
			}
			resolution, resolveErr := runtimeverify.ResolveRoute(options.Runtime.BaseURL, interfaceRoute(item), nil)
			if resolveErr != nil || resolution.RequiresBinding {
				result.Status = testsmodel.StatusUnresolved
				result.Reason = "interface route requires an unavailable runtime binding"
				return result
			}
			page, err = engine.Navigate(ctx, resolution.URL)
			if err != nil {
				result.Status = testsmodel.StatusFailed
				result.Reason = "navigate: " + err.Error()
				addEvidence("test_step", step.InterfaceID, result.Reason, resolution.URL, nil)
				return result
			}
			addEvidence("test_step", step.InterfaceID, "Navigated to canonical interface", page.FinalURL, map[string]string{
				"http_status": strconv.Itoa(page.HTTPStatus), "title": page.Title,
			})
		case "observe":
			addEvidence("test_step", step.InterfaceID, "Observed focused page state", page.FinalURL, map[string]string{
				"http_status": strconv.Itoa(page.HTTPStatus), "title": page.Title,
			})
		default:
			result.Status = testsmodel.StatusUnresolved
			result.Reason = fmt.Sprintf("semantic step %q has no grounded selector binding", step.Type)
			return result
		}
	}
	for _, assertion := range candidate.Assertions {
		if err := evaluateAssertion(assertion, page, authenticated); err != nil {
			result.Status = testsmodel.StatusFailed
			result.Reason = err.Error()
			addEvidence("test_assertion", assertion.InterfaceID, "Assertion failed: "+err.Error(), page.FinalURL, nil)
			return result
		}
		addEvidence("test_assertion", assertion.InterfaceID, "Assertion passed: "+assertion.Type, page.FinalURL, nil)
	}
	result.Status = testsmodel.StatusPassed
	result.Values = NewExecutionState().Values()
	addEvidence("test_execution", "", "Core Test candidate passed", page.FinalURL, nil)
	result.Candidate.EvidenceIDs = append(result.Candidate.EvidenceIDs, result.EvidenceIDs...)
	result.Candidate.EvidenceIDs = sortedUnique(result.Candidate.EvidenceIDs)
	return result
}

func authenticate(
	ctx context.Context,
	engine browser.Engine,
	options ExecutorOptions,
) (browser.Page, error) {
	runtime := options.Runtime
	credentials := options.Credentials
	if credentials == nil {
		return browser.Page{}, fmt.Errorf("authenticated precondition requires configured credentials")
	}
	if runtime.Authentication.LoginURL == "" {
		return browser.Page{}, fmt.Errorf("completed runtime has no verified login URL")
	}
	page, err := engine.Navigate(ctx, runtime.Authentication.LoginURL)
	if err != nil {
		return page, fmt.Errorf("navigate to login surface: %w", err)
	}
	login, ok := browser.DetectLoginForm(page)
	if !ok {
		return page, fmt.Errorf("verified login surface no longer contains a deterministic login form")
	}
	page, err = engine.SubmitLogin(ctx, login, *credentials)
	if err != nil {
		return page, fmt.Errorf("submit login: %w", err)
	}
	completed, secondErr := authn.CompleteSecondFactor(ctx, engine, page, authn.Identity{
		Primary: *credentials, TOTP: options.TOTP, LookupEnv: options.LookupEnv,
	}, authn.Options{SourceSupportsTOTP: runtime.Authentication.SecondFactor != nil,
		RegisterSecrets: options.RegisterSecrets})
	page = completed.Page
	if secondErr != nil {
		return page, secondErr
	}
	if _, stillLogin := browser.DetectLoginForm(page); stillLogin {
		return page, fmt.Errorf("authentication failed: login form remained")
	}
	return page, nil
}

func evaluateAssertion(assertion testsmodel.Assertion, page browser.Page, authenticated bool) error {
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
		matched := false
		switch match {
		case "exact":
			matched = page.Title == assertion.Expected
		case "prefix":
			matched = strings.HasPrefix(page.Title, assertion.Expected)
		case "contains":
			matched = strings.Contains(page.Title, assertion.Expected)
		}
		if !matched {
			if match == "exact" {
				return fmt.Errorf("page title did not exactly match expected %q", assertion.Expected)
			}
			return fmt.Errorf("page title did not match expected safe %s %q", match, assertion.Expected)
		}
	case "url_matches":
		if !sameURL(page.FinalURL, assertion.Expected) {
			return fmt.Errorf("final URL %q does not match %q", page.FinalURL, assertion.Expected)
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
			return fmt.Errorf("page does not contain %q", assertion.Expected)
		}
	default:
		return fmt.Errorf("unsupported assertion %q", assertion.Type)
	}
	return nil
}

func hasLoginForm(page browser.Page) bool {
	_, ok := browser.DetectLoginForm(page)
	return ok
}

func pageContains(page browser.Page, expected string) bool {
	expected = strings.ToLower(expected)
	for _, element := range page.Elements {
		if strings.Contains(strings.ToLower(element.Role+" "+element.Name+" "+element.Text), expected) {
			return true
		}
	}
	return false
}

func sameURL(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return left == right
	}
	leftURL.Fragment, rightURL.Fragment = "", ""
	return leftURL.String() == rightURL.String()
}

func interfaceRoute(item surface.Interface) string {
	if item.Locator.Path != "" {
		return item.Locator.Path
	}
	return item.Locator.TransportPath
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) < 2 {
		return result
	}
	write := 1
	for _, value := range result[1:] {
		if value != result[write-1] {
			result[write] = value
			write++
		}
	}
	return result[:write]
}
