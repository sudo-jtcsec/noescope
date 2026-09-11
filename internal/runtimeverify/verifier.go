package runtimeverify

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

type VerifyOptions struct {
	Application   *model.Application
	Runtime       *Runtime
	RuntimeRoot   string
	Browser       browser.Engine
	Evidence      *EvidenceStore
	Redactor      *Redactor
	IdentityID    string
	Credentials   *browser.Credentials
	MaxInterfaces int
	Logf          func(string, ...any)
}

type verificationCandidate struct {
	item           surface.Interface
	classification SafetyClassification
}

func Verify(ctx context.Context, options VerifyOptions) (resultErr error) {
	if options.Application == nil || options.Runtime == nil || options.Browser == nil ||
		options.Evidence == nil || options.Redactor == nil {
		return fmt.Errorf("runtime verification requires application, runtime, browser, evidence, and redactor")
	}
	if err := ValidateSourceReferences(options.Application); err != nil {
		return err
	}
	if options.MaxInterfaces <= 0 {
		options.MaxInterfaces = 10
	}
	defer options.Browser.Close()
	defer func() {
		if resultErr != nil && options.Runtime.Status == RunStatusRunning {
			MarkFailure(
				options.Runtime, "runtime", "verification",
				options.Redactor.String(resultErr.Error()), nil,
			)
		}
	}()
	state := &DiscoveryState{}

	basePage, err := options.Browser.Navigate(ctx, options.Runtime.BaseURL)
	if err != nil {
		evidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", Summary: "Application reachability failed: " + options.Redactor.String(err.Error()),
			URL: options.Runtime.BaseURL,
		})
		if evidenceErr != nil {
			return evidenceErr
		}
		options.Runtime.Application = ApplicationObservation{
			Reachable: false, Status: StatusRuntimeError, EvidenceIDs: []string{evidence.ID},
		}
		authEvidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", Summary: "Authentication was not executed because the application was unreachable",
		})
		if evidenceErr != nil {
			return evidenceErr
		}
		options.Runtime.Authentication = AuthenticationObservation{
			Attempted: false, Status: StatusNotAttempted, Identity: options.IdentityID,
			Reason: "application was unreachable", EvidenceIDs: []string{authEvidence.ID},
		}
		for _, item := range options.Application.Surface.Interfaces {
			classification := ClassifyInterface(item)
			skipEvidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
				Kind: "runtime_assertion", InterfaceID: item.ID,
				Summary: "Interface was not executed because the application was unreachable",
			})
			if evidenceErr != nil {
				return evidenceErr
			}
			options.Runtime.Interfaces = append(options.Runtime.Interfaces, InterfaceObservation{
				InterfaceID: item.ID, State: "not_attempted", Safety: classification.Safety,
				Status: StatusNotAttempted, Reason: "application was unreachable",
				EvidenceIDs: []string{skipEvidence.ID},
			})
		}
		options.Runtime.Features = FeatureCoverage(options.Application, options.Runtime.Interfaces)
		MarkFailure(
			options.Runtime, "application", "navigation",
			options.Redactor.String(err.Error()), []string{evidence.ID},
		)
		normalizeRuntime(options.Runtime)
		if validationErr := ValidateRuntime(options.Application, options.Runtime, options.Evidence); validationErr != nil {
			return validationErr
		}
		return fmt.Errorf("application is not reachable: %w", err)
	}
	baseEvidence, err := recordPageEvidence(options, "", "unauthenticated", basePage)
	if err != nil {
		return err
	}
	state.Observe(basePage, baseEvidence[0], options.Redactor)
	applicationReachable := basePage.Ready && (basePage.HTTPStatus == 0 || basePage.HTTPStatus < 500)
	applicationStatus := StatusVerified
	if basePage.HTTPStatus == 404 {
		applicationStatus = StatusNotFound
	} else if !applicationReachable {
		applicationStatus = StatusRuntimeError
	}
	options.Runtime.Application = ApplicationObservation{
		Reachable: applicationReachable,
		Status:    applicationStatus, FinalURL: options.Redactor.URL(basePage.FinalURL),
		HTTPStatus: basePage.HTTPStatus, Title: options.Redactor.String(basePage.Title),
		EvidenceIDs: baseEvidence,
	}
	if options.Logf != nil {
		options.Logf("[runtime] application reachability: %s", applicationStatus)
	}

	interfaces := append([]surface.Interface(nil), options.Application.Surface.Interfaces...)
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].ID < interfaces[j].ID })
	candidates := make([]verificationCandidate, 0)
	for _, item := range interfaces {
		classification := ClassifyInterface(item)
		if !BrowserNavigable(item, classification) {
			reason := classification.Reason
			status := StatusNotAttempted
			if classification.Safety == SafetySafe {
				reason = "safe interface is not directly browser-navigable"
			}
			evidence, err := options.Evidence.Add(EvidenceRecord{
				Kind: "runtime_assertion", InterfaceID: item.ID,
				Summary: "Interface was not executed: " + reason,
			})
			if err != nil {
				return err
			}
			options.Runtime.Interfaces = append(options.Runtime.Interfaces, InterfaceObservation{
				InterfaceID: item.ID, State: "not_attempted", Safety: classification.Safety,
				Status: status, Reason: reason, EvidenceIDs: []string{evidence.ID},
			})
			continue
		}
		candidates = append(candidates, verificationCandidate{item, classification})
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := verificationPriority(candidates[i].item), verificationPriority(candidates[j].item)
		if left != right {
			return left < right
		}
		return candidates[i].item.ID < candidates[j].item.ID
	})

	attempted := map[string]struct{}{}
	deferredAuthenticated := make([]verificationCandidate, 0)
	for pass := 0; pass < 2; pass++ {
		for _, candidate := range candidates {
			hasParameters := len(routeParameterNames(interfaceRoute(candidate.item))) > 0
			if (pass == 0 && hasParameters) || (pass == 1 && !hasParameters) {
				continue
			}
			if len(attempted) >= options.MaxInterfaces {
				continue
			}
			observation := verifyInterface(ctx, options, state, candidate.item, candidate.classification, "unauthenticated")
			options.Runtime.Interfaces = append(options.Runtime.Interfaces, observation)
			attempted[candidate.item.ID] = struct{}{}
			if requiresAuthentication(candidate.item) {
				deferredAuthenticated = append(deferredAuthenticated, candidate)
			}
		}
	}
	for _, candidate := range candidates {
		if _, ok := attempted[candidate.item.ID]; !ok {
			reason := fmt.Sprintf("development limit of %d interfaces reached", options.MaxInterfaces)
			evidence, err := options.Evidence.Add(EvidenceRecord{
				Kind: "runtime_assertion", InterfaceID: candidate.item.ID,
				Summary: "Interface was not executed: " + reason,
			})
			if err != nil {
				return err
			}
			options.Runtime.Interfaces = append(options.Runtime.Interfaces, InterfaceObservation{
				InterfaceID: candidate.item.ID, State: "not_attempted", Safety: candidate.classification.Safety,
				Status: StatusNotAttempted, Reason: reason,
				EvidenceIDs: []string{evidence.ID},
			})
		}
	}

	options.Runtime.Authentication = verifyAuthentication(ctx, options, state, basePage)
	if options.Logf != nil {
		options.Logf("[runtime] authentication: %s", options.Runtime.Authentication.Status)
	}
	if options.Runtime.Authentication.Status == StatusVerified {
		state.Authenticated = true
		for _, candidate := range deferredAuthenticated {
			observation := verifyInterface(ctx, options, state, candidate.item, candidate.classification, "authenticated")
			options.Runtime.Interfaces = append(options.Runtime.Interfaces, observation)
		}
	}
	options.Runtime.Features = FeatureCoverage(options.Application, options.Runtime.Interfaces)
	options.Runtime.Status = RunStatusCompleted
	if len(options.Runtime.ObservationErrors) > 0 {
		options.Runtime.Status = RunStatusPartial
	}
	normalizeRuntime(options.Runtime)
	if options.Logf != nil {
		summary := Summarize(options.Runtime)
		options.Logf(
			"[runtime] interfaces: attempted=%d verified=%d skipped_mutating=%d requires_binding=%d",
			summary.SafeInterfacesAttempted, summary.Verified,
			summary.SkippedMutating, summary.RequiresBinding,
		)
	}
	if err := ValidateRuntime(options.Application, options.Runtime, options.Evidence); err != nil {
		MarkFailure(
			options.Runtime, "runtime", "validation",
			options.Redactor.String(err.Error()), nil,
		)
		return err
	}
	return nil
}

func verifyAuthentication(
	ctx context.Context,
	options VerifyOptions,
	state *DiscoveryState,
	basePage browser.Page,
) AuthenticationObservation {
	result := AuthenticationObservation{
		Attempted: false, Status: StatusNotAttempted, Identity: options.IdentityID,
		EvidenceIDs: []string{},
	}
	if !options.Application.Identity.Authentication.AuthenticationPresent {
		result.Reason = "source model does not predict authentication"
		addAuthenticationAssertion(options, &result)
		return result
	}
	if options.Credentials == nil || options.IdentityID == "" {
		result.Reason = "runtime identity credentials are not configured"
		addAuthenticationAssertion(options, &result)
		return result
	}
	pages := []browser.Page{basePage}
	if _, ok := browser.DetectLoginForm(basePage); !ok {
		for _, candidateURL := range loginCandidateURLs(options.Application, options.Runtime.BaseURL) {
			page, err := options.Browser.Navigate(ctx, candidateURL)
			if err != nil {
				continue
			}
			evidenceIDs, err := recordPageEvidence(options, "", "login_discovery", page)
			if err != nil {
				result.Status = StatusRuntimeError
				result.Reason = err.Error()
				return result
			}
			state.Observe(page, evidenceIDs[0], options.Redactor)
			result.EvidenceIDs = append(result.EvidenceIDs, evidenceIDs...)
			pages = append(pages, page)
			if _, ok := browser.DetectLoginForm(page); ok {
				break
			}
		}
	}
	var login browser.LoginForm
	found := false
	for _, page := range pages {
		if login, found = browser.DetectLoginForm(page); found {
			break
		}
	}
	if !found {
		result.Reason = "no deterministic username/password login form was found"
		addAuthenticationAssertion(options, &result)
		return result
	}
	result.Attempted = true
	result.LoginURL = options.Redactor.URL(login.PageURL)
	formEvidence, err := options.Evidence.Add(EvidenceRecord{
		Kind: "dom_observation", Summary: "Detected login form with username and password controls; values were not captured",
		URL: login.PageURL, Attributes: loginFormEvidenceAttributes(login.Form),
	})
	if err != nil {
		result.Status = StatusRuntimeError
		result.Reason = err.Error()
		return result
	}
	result.EvidenceIDs = append(result.EvidenceIDs, formEvidence.ID)
	page, err := options.Browser.SubmitLogin(ctx, login, *options.Credentials)
	if err != nil {
		result.Status = StatusRuntimeError
		result.Reason = options.Redactor.String(err.Error())
		return result
	}
	evidenceIDs, err := recordPageEvidence(options, "", "authenticated", page)
	if err != nil {
		result.Status = StatusRuntimeError
		result.Reason = err.Error()
		return result
	}
	result.EvidenceIDs = append(result.EvidenceIDs, evidenceIDs...)
	result.FinalURL = options.Redactor.URL(page.FinalURL)
	state.Observe(page, evidenceIDs[0], options.Redactor)
	_, stillLogin := browser.DetectLoginForm(page)
	if !stillLogin && (differentURL(login.PageURL, page.FinalURL) || len(page.Cookies) > 0 || authenticatedIndicator(page)) {
		result.Status = StatusVerified
		return result
	}
	if !stillLogin && hasObservationError(page, "cookies") {
		result.Status = StatusUnknown
		result.Reason = "login completed but authentication evidence was insufficient because cookie inspection failed"
		return result
	}
	result.Status = StatusUnverified
	result.Reason = "login form remained or no authenticated session indicator was observed"
	return result
}

func loginFormEvidenceAttributes(form browser.Form) map[string]string {
	values := map[string]string{
		"action":                form.Action,
		"method":                form.Method,
		"username_name":         form.UsernameField,
		"username_id":           form.UsernameID,
		"username_type":         form.UsernameType,
		"username_autocomplete": form.UsernameAutocomplete,
		"password_name":         form.PasswordField,
		"password_id":           form.PasswordID,
		"password_type":         form.PasswordType,
		"password_autocomplete": form.PasswordAutocomplete,
		"submit_type":           form.SubmitType,
		"submit_text":           form.SubmitLabel,
	}
	for key, value := range values {
		if value == "" {
			delete(values, key)
		}
	}
	return values
}

func verifyInterface(
	ctx context.Context,
	options VerifyOptions,
	state *DiscoveryState,
	item surface.Interface,
	classification SafetyClassification,
	browserState string,
) InterfaceObservation {
	result := InterfaceObservation{
		InterfaceID: item.ID, State: browserState, Safety: classification.Safety,
		EvidenceIDs: []string{},
	}
	resolution, err := ResolveRoute(options.Runtime.BaseURL, interfaceRoute(item), state)
	if err != nil {
		result.Status = StatusUnknown
		result.Reason = err.Error()
		if evidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: item.ID,
			Summary: "Interface URL could not be resolved: " + result.Reason,
		}); evidenceErr == nil {
			result.EvidenceIDs = append(result.EvidenceIDs, evidence.ID)
		}
		return result
	}
	if resolution.RequiresBinding {
		result.Status = StatusRequiresRuntimeBinding
		result.Reason = "route parameters were not observed in previously verified links"
		if evidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: item.ID,
			Summary: "Interface was not executed: " + result.Reason,
		}); evidenceErr == nil {
			result.EvidenceIDs = append(result.EvidenceIDs, evidence.ID)
		}
		return result
	}
	result.RequestedURL = options.Redactor.URL(resolution.URL)
	if len(resolution.Bindings) > 0 {
		evidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: item.ID,
			Summary: "Bound route parameters from an observed same-origin link",
			URL:     resolution.URL, Attributes: resolution.Bindings,
		})
		if evidenceErr == nil {
			result.EvidenceIDs = append(result.EvidenceIDs, resolution.EvidenceIDs...)
			result.EvidenceIDs = append(result.EvidenceIDs, evidence.ID)
		}
	}
	page, err := options.Browser.Navigate(ctx, resolution.URL)
	if err != nil {
		result.Status = StatusRuntimeError
		result.Reason = options.Redactor.String(err.Error())
		if evidence, evidenceErr := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: item.ID,
			Summary: "Interface navigation failed: " + result.Reason,
			URL:     resolution.URL,
		}); evidenceErr == nil {
			result.EvidenceIDs = append(result.EvidenceIDs, evidence.ID)
		}
		captureFailureScreenshot(options, item.ID, &result)
		return result
	}
	evidenceIDs, err := recordPageEvidence(options, item.ID, browserState, page)
	if err != nil {
		result.Status = StatusRuntimeError
		result.Reason = err.Error()
		return result
	}
	result.EvidenceIDs = append(result.EvidenceIDs, evidenceIDs...)
	state.Observe(page, evidenceIDs[0], options.Redactor)
	result.FinalURL = options.Redactor.URL(page.FinalURL)
	result.HTTPStatus = page.HTTPStatus
	result.Title = options.Redactor.String(page.Title)
	for _, element := range page.Elements {
		if len(result.Elements) >= 12 {
			break
		}
		result.Elements = append(result.Elements, SemanticElement{
			Role: options.Redactor.String(element.Role), Name: options.Redactor.String(element.Name),
			Text: options.Redactor.String(element.Text),
		})
	}
	loginRedirect := isLoginPage(page)
	switch {
	case page.HTTPStatus == 404:
		result.Status = StatusNotFound
		result.Reason = "runtime returned HTTP 404"
		captureFailureScreenshot(options, item.ID, &result)
	case page.HTTPStatus >= 400:
		result.Status = StatusRuntimeError
		result.Reason = fmt.Sprintf("runtime returned HTTP %d", page.HTTPStatus)
		captureFailureScreenshot(options, item.ID, &result)
	case browserState == "unauthenticated" && requiresAuthentication(item) && !loginRedirect:
		result.Status = StatusContradicted
		result.Reason = "source requires authentication but the interface was reachable anonymously"
	case loginRedirect:
		if item.Access != nil && item.Access.Authentication == "not_required" {
			result.Status = StatusContradicted
			result.Reason = "source marks interface public but runtime required authentication"
		} else {
			result.Status = StatusAuthRequired
			result.Reason = "runtime redirected to a login form"
		}
	case differentURL(resolution.URL, page.FinalURL):
		result.Status = StatusRedirected
		result.Reason = "runtime navigated to a different URL"
	default:
		result.Status = StatusVerified
	}
	return result
}

func recordPageEvidence(
	options VerifyOptions,
	interfaceID, state string,
	page browser.Page,
) ([]string, error) {
	navigation, err := options.Evidence.Add(EvidenceRecord{
		Kind: "browser_navigation", InterfaceID: interfaceID,
		Summary: fmt.Sprintf("Browser navigation completed in %s state with HTTP status %d", state, page.HTTPStatus),
		URL:     page.FinalURL, Attributes: map[string]string{"title": page.Title},
	})
	if err != nil {
		return nil, err
	}
	evidenceIDs := []string{navigation.ID}
	phase := "application"
	if interfaceID != "" {
		phase = "interface"
	} else if state == "login_discovery" || state == "authenticated" {
		phase = "authentication"
	}
	for _, observationErr := range page.ObservationErrors {
		message := options.Redactor.String(observationErr.Error())
		record, err := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: interfaceID,
			Summary: "Optional browser observation failed: " + message,
			URL:     page.FinalURL, Attributes: map[string]string{
				"phase": phase, "operation": observationErr.Operation, "state": state,
			},
		})
		if err != nil {
			return nil, err
		}
		options.Runtime.ObservationErrors = append(options.Runtime.ObservationErrors, ObservationError{
			Phase: phase, Operation: observationErr.Operation, InterfaceID: interfaceID,
			State: state, Message: message, EvidenceID: record.ID,
		})
		evidenceIDs = append(evidenceIDs, record.ID)
	}
	if len(page.Elements) > 0 || len(page.Forms) > 0 {
		dom, err := options.Evidence.Add(EvidenceRecord{
			Kind: "dom_observation", InterfaceID: interfaceID,
			Summary: fmt.Sprintf("Observed %d focused semantic elements and %d forms", len(page.Elements), len(page.Forms)),
			URL:     page.FinalURL,
		})
		if err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, dom.ID)
	}
	ariaElements := 0
	for _, element := range page.Elements {
		if element.Role != "" || element.Name != "" {
			ariaElements++
		}
	}
	if ariaElements > 0 {
		accessibility, err := options.Evidence.Add(EvidenceRecord{
			Kind: "accessibility_observation", InterfaceID: interfaceID,
			Summary: fmt.Sprintf("Observed %d focused semantic or accessibility-labelled elements", ariaElements),
			URL:     page.FinalURL,
		})
		if err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, accessibility.ID)
	}
	for index, networkItem := range page.Network {
		if index >= 20 {
			break
		}
		request, err := options.Evidence.Add(EvidenceRecord{
			Kind: "network_request", InterfaceID: interfaceID,
			Summary: "Observed focused browser network request",
			URL:     networkItem.URL, Attributes: map[string]string{
				"method": networkItem.Method, "resource_type": networkItem.Type,
			},
		})
		if err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, request.ID)
		if networkItem.Status != 0 {
			response, err := options.Evidence.Add(EvidenceRecord{
				Kind: "network_response", InterfaceID: interfaceID,
				Summary: fmt.Sprintf("Observed focused browser network response with HTTP status %d", networkItem.Status),
				URL:     networkItem.URL, Attributes: map[string]string{"resource_type": networkItem.Type},
			})
			if err != nil {
				return nil, err
			}
			evidenceIDs = append(evidenceIDs, response.ID)
		}
	}
	if len(page.Cookies) > 0 {
		names := make([]string, 0, len(page.Cookies))
		for _, cookie := range page.Cookies {
			names = append(names, cookie.Name)
		}
		sort.Strings(names)
		session, err := options.Evidence.Add(EvidenceRecord{
			Kind: "runtime_assertion", InterfaceID: interfaceID,
			Summary: fmt.Sprintf("Observed %d browser cookies; values were not captured", len(page.Cookies)),
			URL:     page.FinalURL, Attributes: map[string]string{"cookie_names": strings.Join(names, ",")},
		})
		if err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, session.ID)
	}
	for _, message := range page.ConsoleErrors {
		if len(options.Runtime.ConsoleErrors) >= 50 {
			break
		}
		record, err := options.Evidence.Add(EvidenceRecord{
			Kind: "console_message", InterfaceID: interfaceID,
			Summary: options.Redactor.String(message), URL: page.FinalURL,
		})
		if err != nil {
			return nil, err
		}
		options.Runtime.ConsoleErrors = append(options.Runtime.ConsoleErrors, ConsoleObservation{
			InterfaceID: interfaceID, State: state,
			Message: options.Redactor.String(message), EvidenceID: record.ID,
		})
		evidenceIDs = append(evidenceIDs, record.ID)
	}
	return evidenceIDs, nil
}

func captureFailureScreenshot(options VerifyOptions, interfaceID string, observation *InterfaceObservation) {
	// Pixel redaction is not reliable. When an identity is configured, avoid
	// automatic screenshots entirely so a rendered username or credential value
	// cannot escape string redaction.
	if options.Credentials != nil {
		return
	}
	name := safeFilename(interfaceID) + ".png"
	path := filepath.Join(options.RuntimeRoot, "screenshots", name)
	if err := options.Browser.Screenshot(context.Background(), path); err != nil {
		return
	}
	record, err := options.Evidence.Add(EvidenceRecord{
		Kind: "screenshot", InterfaceID: interfaceID,
		Summary:    "Captured screenshot after interface verification failure",
		Attributes: map[string]string{"path": filepath.ToSlash(filepath.Join("screenshots", name))},
	})
	if err == nil {
		observation.EvidenceIDs = append(observation.EvidenceIDs, record.ID)
	}
}

func interfaceRoute(item surface.Interface) string {
	if item.Locator.Path != "" {
		return item.Locator.Path
	}
	return item.Locator.TransportPath
}

func requiresAuthentication(item surface.Interface) bool {
	return item.Access != nil && item.Access.Authentication == "required"
}

func isLoginPage(page browser.Page) bool {
	if _, ok := browser.DetectLoginForm(page); ok {
		return true
	}
	parsed, _ := url.Parse(page.FinalURL)
	return strings.Contains(strings.ToLower(parsed.Path), "login")
}

func differentURL(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return left != right
	}
	leftURL.Fragment = ""
	rightURL.Fragment = ""
	return leftURL.String() != rightURL.String()
}

func authenticatedIndicator(page browser.Page) bool {
	for _, element := range page.Elements {
		value := strings.ToLower(element.Name + " " + element.Text)
		if strings.Contains(value, "logout") || strings.Contains(value, "log out") ||
			strings.Contains(value, "profile") || strings.Contains(value, "account") {
			return true
		}
	}
	return false
}

func hasObservationError(page browser.Page, operation string) bool {
	for _, observationErr := range page.ObservationErrors {
		if observationErr.Operation == operation {
			return true
		}
	}
	return false
}

func loginCandidateURLs(application *model.Application, baseURL string) []string {
	paths := make([]string, 0)
	interfaces := map[string]surface.Interface{}
	for _, item := range application.Surface.Interfaces {
		interfaces[item.ID] = item
		semantic := strings.ToLower(item.ID + " " + item.Name + " " + item.Description)
		if (item.Type == "web_page" || item.Type == "form_action") &&
			(containsWord(semantic, []string{"login", "signin", "authenticate"})) {
			if route := interfaceRoute(item); route != "" {
				if resolved, err := ResolveRoute(baseURL, route, nil); err == nil && !resolved.RequiresBinding {
					paths = appendUniqueSorted(paths, resolved.URL)
				}
			}
		}
	}
	for _, mechanism := range application.Identity.Authentication.Mechanisms {
		if mechanism.Type != "form_session" {
			continue
		}
		for _, entrypoint := range mechanism.LoginEntrypoints {
			if item, ok := interfaces[entrypoint]; ok {
				if route := interfaceRoute(item); route != "" {
					if resolved, err := ResolveRoute(baseURL, route, nil); err == nil && !resolved.RequiresBinding {
						paths = appendUniqueSorted(paths, resolved.URL)
					}
				}
			}
			if path := entrypointPath(entrypoint); path != "" {
				if resolved, err := ResolveRoute(baseURL, path, nil); err == nil && !resolved.RequiresBinding {
					paths = appendUniqueSorted(paths, resolved.URL)
				}
			}
		}
	}
	return paths
}

func entrypointPath(value string) string {
	for _, field := range strings.Fields(value) {
		field = strings.Trim(field, "()[]{}.,;`\"")
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") || strings.HasPrefix(field, "/") {
			return field
		}
	}
	return ""
}

func safeFilename(value string) string {
	var result strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			result.WriteRune(character)
		} else {
			result.WriteByte('_')
		}
	}
	if result.Len() == 0 {
		return "runtime"
	}
	return result.String()
}

func verificationPriority(item surface.Interface) int {
	route := interfaceRoute(item)
	semantic := strings.ToLower(item.ID + " " + item.Name + " " + item.Description)
	if route == "/" || strings.HasSuffix(item.ID, ".root") || containsWord(semantic, []string{"dashboard", "home"}) {
		return 0
	}
	if containsWord(semantic, []string{"health", "status"}) {
		return 1
	}
	if item.Access != nil && item.Access.Authentication == "not_required" {
		return 2
	}
	if containsWord(semantic, []string{"list", "view", "show", "get"}) {
		return 3
	}
	return 4
}

func addAuthenticationAssertion(options VerifyOptions, result *AuthenticationObservation) {
	record, err := options.Evidence.Add(EvidenceRecord{
		Kind: "runtime_assertion", Summary: "Authentication was not executed: " + result.Reason,
	})
	if err == nil {
		result.EvidenceIDs = append(result.EvidenceIDs, record.ID)
	}
}
