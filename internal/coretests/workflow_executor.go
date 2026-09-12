package coretests

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/authn"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type WorkflowHooks struct {
	AfterChildCreation func() error
}

type WorkflowExecutorOptions struct {
	ExecutorOptions
	ExecutionID string
	Hooks       WorkflowHooks
}

func ExecuteOwnedLifecycle(
	ctx context.Context,
	plan *OwnedLifecyclePlan,
	options WorkflowExecutorOptions,
) testsmodel.CandidateResult {
	result := testsmodel.CandidateResult{
		Candidate: plan.Test, Status: testsmodel.StatusCandidate,
		EvidenceIDs: []string{}, Values: map[string]string{}, OwnedObjects: []testsmodel.OwnedObject{},
	}
	addEvidence := func(kind, interfaceID, summary, target string, attributes map[string]string) string {
		if options.Evidence == nil {
			return ""
		}
		record, err := options.Evidence.Add(EvidenceRecord{
			Kind: kind, TestID: plan.Test.ID, InterfaceID: interfaceID,
			Summary: summary, URL: target, Attributes: attributes,
		})
		if err != nil {
			return ""
		}
		result.EvidenceIDs = append(result.EvidenceIDs, record.ID)
		return record.ID
	}
	if err := testsmodel.ValidateTest(plan.Test, options.Application); err != nil {
		result.Status, result.Reason = testsmodel.StatusUnresolved, err.Error()
		return result
	}
	if !options.MutationsEnabled {
		result.Status, result.Reason = testsmodel.StatusBlocked, "testing.mutations.enabled=false"
		addEvidence("test_execution", "", "Owned lifecycle was blocked by testing configuration", "", nil)
		return result
	}
	if options.Credentials == nil {
		result.Status, result.Reason = testsmodel.StatusBlocked, options.AuthenticationUnavailableReason
		if result.Reason == "" {
			result.Reason = "configured testing identity credentials are unavailable"
		}
		return result
	}
	if options.BrowserFactory == nil {
		result.Status, result.Reason = testsmodel.StatusUnresolved, "browser factory is unavailable"
		return result
	}
	engine, err := options.BrowserFactory(ctx)
	if err != nil {
		result.Status, result.Reason = testsmodel.StatusFailed, "start browser: "+err.Error()
		return result
	}
	defer engine.Close()
	mutationBrowser, ok := engine.(browser.MutationEngine)
	if !ok {
		result.Status, result.Reason = testsmodel.StatusUnresolved, "browser does not support bounded form mutation"
		return result
	}
	if _, err := authenticate(ctx, engine, options.ExecutorOptions); err != nil {
		result.Status, result.Reason = testsmodel.StatusFailed, err.Error()
		if authn.IsTOTPRequired(err) {
			result.Status = testsmodel.StatusBlocked
		}
		return result
	}
	addEvidence("test_step", "", "Established authenticated workflow precondition", options.Runtime.Authentication.FinalURL, nil)

	state := NewExecutionStateFor(options.ExecutionID, plan.Test.ID)
	declarations := map[string]testsmodel.ValueReference{}
	for _, value := range plan.Test.GeneratedValues {
		declarations[value.Reference] = value
	}
	parentName, err := state.ResolveValue(plan.ParentValueRef, declarations[plan.ParentValueRef])
	if err != nil {
		result.Status, result.Reason = testsmodel.StatusUnresolved, err.Error()
		return result
	}
	childTitle, err := state.ResolveValue(plan.ChildValueRef, declarations[plan.ChildValueRef])
	if err != nil {
		result.Status, result.Reason = testsmodel.StatusUnresolved, err.Error()
		return result
	}
	updatedTitle, err := state.ResolveValue(plan.UpdatedValueRef, declarations[plan.UpdatedValueRef])
	if err != nil {
		result.Status, result.Reason = testsmodel.StatusUnresolved, err.Error()
		return result
	}

	interfaces := make(map[string]surface.Interface, len(options.Application.Surface.Interfaces))
	for _, item := range options.Application.Surface.Interfaces {
		interfaces[item.ID] = item
	}
	bindings := map[string]string{}
	workflowErr := runOwnedWorkflow(ctx, mutationBrowser, plan, interfaces, options.Runtime.BaseURL,
		state, bindings, parentName, childTitle, updatedTitle, addEvidence, options.Hooks)
	if workflowErr != nil {
		result.WorkflowFailure = workflowErr.Error()
	}

	var cleanupErr error
	if options.Cleanup == "always" && len(state.OwnedObjects()) > 0 {
		cleanupCtx := ctx
		if ctx.Err() != nil {
			var cancel context.CancelFunc
			cleanupCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
		}
		cleanupErr = cleanupOwnedWorkflow(cleanupCtx, mutationBrowser, plan, interfaces,
			options.Runtime.BaseURL, state, bindings, addEvidence)
	}
	result.Values = state.Values()
	result.OwnedObjects = state.OwnedObjects()
	result.EvidenceIDs = sortedUnique(result.EvidenceIDs)
	result.Candidate.EvidenceIDs = sortedUnique(append(result.Candidate.EvidenceIDs, result.EvidenceIDs...))
	if cleanupErr != nil {
		result.Status = testsmodel.StatusCleanupFailed
		result.CleanupFailure = cleanupErr.Error()
		result.Reason = cleanupErr.Error()
		if workflowErr != nil {
			result.Reason = workflowErr.Error() + "; cleanup failed: " + cleanupErr.Error()
		}
		return result
	}
	if workflowErr != nil {
		result.Status, result.Reason = testsmodel.StatusFailed, workflowErr.Error()
		return result
	}
	if !allObjectsCleaned(result.OwnedObjects) {
		result.Status, result.Reason = testsmodel.StatusCleanupFailed, "owned objects were not all verified cleaned"
		return result
	}
	result.Status = testsmodel.StatusPassed
	addEvidence("test_execution", "", "Owned parent/child lifecycle and cleanup passed", "", nil)
	result.EvidenceIDs = sortedUnique(result.EvidenceIDs)
	result.Candidate.EvidenceIDs = sortedUnique(append(result.Candidate.EvidenceIDs, result.EvidenceIDs...))
	return result
}

type workflowEvidence func(kind, interfaceID, summary, target string, attributes map[string]string) string

func runOwnedWorkflow(
	ctx context.Context,
	engine browser.MutationEngine,
	plan *OwnedLifecyclePlan,
	interfaces map[string]surface.Interface,
	baseURL string,
	state *ExecutionState,
	bindings map[string]string,
	parentName, childTitle, updatedTitle string,
	addEvidence workflowEvidence,
	hooks WorkflowHooks,
) error {
	parentCreateURL, err := resolveBoundURL(baseURL, interfaces[plan.ParentCreate].Locator.Path, bindings)
	if err != nil {
		return err
	}
	page, err := engine.Navigate(ctx, parentCreateURL)
	if err != nil {
		return fmt.Errorf("open %s creation form: %w", plan.ParentEntity.Name, err)
	}
	form, control, err := bindFormControl(page, []string{"name", "title"})
	if err != nil {
		return fmt.Errorf("bind %s creation form: %w", plan.ParentEntity.Name, err)
	}
	addFormEvidence(addEvidence, plan.ParentCreate, page, form, control)
	page, err = engine.SubmitForm(ctx, browser.FormSubmission{
		PageURL: page.FinalURL, FormSelector: form.Selector, SubmitSelector: form.SubmitSelector,
		Entries: []browser.FormEntry{{Selector: control.Selector, Type: control.Type, Value: parentName}},
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", plan.ParentEntity.Name, err)
	}
	if !pageHasValue(page, parentName) {
		return fmt.Errorf("%s creation was not confirmed by the resulting page", plan.ParentEntity.Name)
	}
	parentID, err := captureRuntimeBinding(page, baseURL, interfaces[plan.ParentView].Locator.Path,
		plan.ParentParameter, parentName)
	if err != nil {
		return fmt.Errorf("capture %s identifier: %w", plan.ParentEntity.Name, err)
	}
	evidenceID := addEvidence("test_assertion", plan.ParentView, "Created parent entity and captured its runtime identifier", page.FinalURL,
		map[string]string{"entity_id": plan.ParentEntity.ID, "runtime_identifier": parentID})
	if err := state.EstablishOwned("created."+plan.ParentEntity.ID, plan.ParentEntity.ID, parentID,
		map[string]string{"name": parentName}, nonEmptyStrings(evidenceID)); err != nil {
		return err
	}
	bindings[plan.ParentParameter] = parentID

	childCreateURL, err := resolveBoundURL(baseURL, interfaces[plan.ChildCreate].Locator.Path, bindings)
	if err != nil {
		return err
	}
	page, err = engine.Navigate(ctx, childCreateURL)
	if err != nil {
		return fmt.Errorf("open %s creation form: %w", plan.ChildEntity.Name, err)
	}
	form, control, err = bindFormControl(page, []string{"title", "name"})
	if err != nil {
		return fmt.Errorf("bind %s creation form: %w", plan.ChildEntity.Name, err)
	}
	addFormEvidence(addEvidence, plan.ChildCreate, page, form, control)
	page, err = engine.SubmitForm(ctx, browser.FormSubmission{
		PageURL: page.FinalURL, FormSelector: form.Selector, SubmitSelector: form.SubmitSelector,
		Entries: []browser.FormEntry{{Selector: control.Selector, Type: control.Type, Value: childTitle}},
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", plan.ChildEntity.Name, err)
	}
	if !pageHasValue(page, childTitle) {
		return fmt.Errorf("%s creation was not confirmed by the resulting page", plan.ChildEntity.Name)
	}
	childID, err := captureRuntimeBinding(page, baseURL, interfaces[plan.ChildView].Locator.Path,
		plan.ChildParameter, childTitle)
	if err != nil {
		return fmt.Errorf("capture %s identifier: %w", plan.ChildEntity.Name, err)
	}
	evidenceID = addEvidence("test_assertion", plan.ChildView, "Created child entity and captured its runtime identifier", page.FinalURL,
		map[string]string{"entity_id": plan.ChildEntity.ID, "runtime_identifier": childID})
	if err := state.EstablishOwned("created."+plan.ChildEntity.ID, plan.ChildEntity.ID, childID,
		map[string]string{"title": childTitle}, nonEmptyStrings(evidenceID)); err != nil {
		return err
	}
	bindings[plan.ChildParameter] = childID
	if hooks.AfterChildCreation != nil {
		if err := hooks.AfterChildCreation(); err != nil {
			return err
		}
	}

	if _, err := state.RequireOwned("created." + plan.ChildEntity.ID); err != nil {
		return err
	}
	childEditURL, err := resolveBoundURL(baseURL, interfaces[plan.ChildEdit].Locator.Path, bindings)
	if err != nil {
		return err
	}
	page, err = engine.Navigate(ctx, childEditURL)
	if err != nil {
		return fmt.Errorf("open %s edit form: %w", plan.ChildEntity.Name, err)
	}
	form, control, err = bindFormControl(page, []string{"title", "name"})
	if err != nil {
		return fmt.Errorf("bind %s update form: %w", plan.ChildEntity.Name, err)
	}
	addFormEvidence(addEvidence, plan.ChildUpdate, page, form, control)
	page, err = engine.SubmitForm(ctx, browser.FormSubmission{
		PageURL: page.FinalURL, FormSelector: form.Selector, SubmitSelector: form.SubmitSelector,
		Entries: []browser.FormEntry{{Selector: control.Selector, Type: control.Type, Value: updatedTitle}},
	})
	if err != nil {
		return fmt.Errorf("update %s: %w", plan.ChildEntity.Name, err)
	}
	if !pageHasValue(page, updatedTitle) {
		return fmt.Errorf("%s update was not confirmed by the resulting page", plan.ChildEntity.Name)
	}
	if err := state.UpdateOwnedFields("created."+plan.ChildEntity.ID, map[string]string{"title": updatedTitle}); err != nil {
		return err
	}
	addEvidence("test_assertion", plan.ChildView, "Owned child update was verified", page.FinalURL,
		map[string]string{"entity_id": plan.ChildEntity.ID, "runtime_identifier": childID})
	return nil
}

func cleanupOwnedWorkflow(
	ctx context.Context,
	engine browser.MutationEngine,
	plan *OwnedLifecyclePlan,
	interfaces map[string]surface.Interface,
	baseURL string,
	state *ExecutionState,
	bindings map[string]string,
	addEvidence workflowEvidence,
) error {
	steps := []ownedCleanupStep{
		{plan.ChildEntity.ID, plan.ChildEntity.Name, plan.ChildRemove, plan.ChildView, "created." + plan.ChildEntity.ID},
		{plan.ParentEntity.ID, plan.ParentEntity.Name, plan.ParentRemove, plan.ParentView, "created." + plan.ParentEntity.ID},
	}
	var failures []string
	for _, step := range steps {
		if !state.Owns(step.reference) {
			continue
		}
		if err := cleanupOwnedObject(ctx, engine, interfaces, baseURL, state, bindings, addEvidence, step); err != nil {
			_ = state.MarkCleanup(step.reference, "failed", nil)
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

type ownedCleanupStep struct {
	entityID    string
	entityName  string
	interfaceID string
	viewID      string
	reference   string
}

func cleanupOwnedObject(
	ctx context.Context,
	engine browser.MutationEngine,
	interfaces map[string]surface.Interface,
	baseURL string,
	state *ExecutionState,
	bindings map[string]string,
	addEvidence workflowEvidence,
	step ownedCleanupStep,
) error {
	runtimeID, err := state.RequireOwned(step.reference)
	if err != nil {
		return err
	}
	confirmURL, err := resolveBoundURL(baseURL, interfaces[step.interfaceID].Locator.Path, bindings)
	if err != nil {
		return err
	}
	page, err := engine.Navigate(ctx, confirmURL)
	if err != nil {
		return fmt.Errorf("open %s cleanup confirmation: %w", step.entityName, err)
	}
	activation, err := bindDestructiveConfirmation(page)
	if err != nil {
		return fmt.Errorf("bind %s cleanup confirmation: %w", step.entityName, err)
	}
	page, err = engine.Activate(ctx, activation)
	if err != nil {
		return fmt.Errorf("delete owned %s: %w", step.entityName, err)
	}
	viewURL, err := resolveBoundURL(baseURL, interfaces[step.viewID].Locator.Path, bindings)
	if err != nil {
		return err
	}
	verification, verifyErr := engine.Navigate(ctx, viewURL)
	if verifyErr != nil {
		return fmt.Errorf("verify %s cleanup: %w", step.entityName, verifyErr)
	}
	if !objectUnavailable(verification, viewURL) {
		return fmt.Errorf("cleanup verification failed for owned %s %s", step.entityName, runtimeID)
	}
	evidenceID := addEvidence("test_cleanup", step.interfaceID, "Owned entity cleanup verified", page.FinalURL,
		map[string]string{"entity_id": step.entityID, "runtime_identifier": runtimeID, "confirmation": activation.Label})
	if err := state.MarkCleanup(step.reference, "verified", nonEmptyStrings(evidenceID)); err != nil {
		return err
	}
	return nil
}

func resolveBoundURL(baseURL, path string, bindings map[string]string) (string, error) {
	resolvedPath := path
	for _, parameter := range routeParameterNames(path) {
		value := bindings[parameter]
		if value == "" {
			return "", fmt.Errorf("route %q requires unproven binding %q", path, parameter)
		}
		resolvedPath = strings.ReplaceAll(resolvedPath, "{"+parameter+"}", url.PathEscape(value))
	}
	resolution, err := runtimeverify.ResolveRoute(baseURL, resolvedPath, nil)
	if err != nil {
		return "", err
	}
	return resolution.URL, nil
}

func captureRuntimeBinding(page browser.Page, baseURL, template, parameter, expectedText string) (string, error) {
	candidates := []browser.Link{{URL: page.FinalURL, Text: strings.Join(elementTexts(page.Elements), " ")}}
	candidates = append(candidates, page.Links...)
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	for _, candidate := range candidates {
		if candidate.URL == "" || (expectedText != "" && candidate.URL != page.FinalURL &&
			!strings.Contains(strings.ToLower(candidate.Text), strings.ToLower(expectedText))) {
			continue
		}
		parsed, err := url.Parse(candidate.URL)
		if err != nil || !sameURLOrigin(base, parsed) {
			continue
		}
		bindings, ok := matchRouteTemplate(template, parsed.Path)
		if ok && bindings[parameter] != "" {
			return bindings[parameter], nil
		}
	}
	return "", fmt.Errorf("no same-origin canonical route observation supplied %q", parameter)
}

func matchRouteTemplate(template, observedPath string) (map[string]string, bool) {
	templateParts := strings.Split(strings.Trim(template, "/"), "/")
	observedParts := strings.Split(strings.Trim(observedPath, "/"), "/")
	if len(templateParts) != len(observedParts) {
		return nil, false
	}
	bindings := map[string]string{}
	for index, part := range templateParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			value, err := url.PathUnescape(observedParts[index])
			if err != nil || value == "" {
				return nil, false
			}
			bindings[strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")] = value
		} else if part != observedParts[index] {
			return nil, false
		}
	}
	return bindings, true
}

func bindFormControl(page browser.Page, terms []string) (browser.Form, browser.FormControl, error) {
	type match struct {
		form    browser.Form
		control browser.FormControl
		score   int
	}
	matches := []match{}
	for _, form := range page.Forms {
		if form.SubmitSelector == "" {
			continue
		}
		for _, control := range form.Controls {
			if control.Type != "text" && control.Type != "textarea" && control.Type != "email" && control.Type != "" {
				continue
			}
			haystack := strings.ToLower(control.Name + " " + control.ID + " " + control.Label)
			score := 0
			for index, term := range terms {
				term = strings.ToLower(term)
				if strings.EqualFold(control.Name, term) || strings.EqualFold(control.ID, term) {
					score = 100 - index
					break
				}
				if strings.Contains(haystack, term) && score < 50-index {
					score = 50 - index
				}
			}
			if score > 0 {
				matches = append(matches, match{form: form, control: control, score: score})
			}
		}
	}
	if len(matches) == 0 {
		return browser.Form{}, browser.FormControl{}, fmt.Errorf("no stable semantic form control matched %v", terms)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].control.Selector < matches[j].control.Selector
	})
	return matches[0].form, matches[0].control, nil
}

func bindDestructiveConfirmation(page browser.Page) (browser.Activation, error) {
	priority := []string{"yes", "confirm", "delete", "remove"}
	for _, wanted := range priority {
		for _, link := range page.Links {
			label := strings.TrimSpace(strings.ToLower(link.Text))
			if label == wanted && link.Selector != "" {
				return browser.Activation{PageURL: page.FinalURL, Selector: link.Selector, Label: link.Text}, nil
			}
		}
	}
	return browser.Activation{}, fmt.Errorf("no deterministic destructive confirmation control was observed")
}

func addFormEvidence(addEvidence workflowEvidence, interfaceID string, page browser.Page, form browser.Form, control browser.FormControl) {
	addEvidence("test_step", interfaceID, "Bound live form using safe control metadata", page.FinalURL, map[string]string{
		"form_action": form.Action, "form_method": form.Method,
		"control_id": control.ID, "control_name": control.Name,
		"control_type": control.Type, "control_label": control.Label,
	})
}

func pageHasValue(page browser.Page, value string) bool {
	value = strings.ToLower(value)
	for _, text := range elementTexts(page.Elements) {
		if strings.Contains(strings.ToLower(text), value) {
			return true
		}
	}
	for _, link := range page.Links {
		if strings.Contains(strings.ToLower(link.Text), value) {
			return true
		}
	}
	return false
}

func elementTexts(elements []browser.Element) []string {
	result := make([]string, 0, len(elements))
	for _, element := range elements {
		result = append(result, element.Name+" "+element.Text)
	}
	return result
}

func objectUnavailable(page browser.Page, requestedURL string) bool {
	if page.HTTPStatus == 404 || page.HTTPStatus == 410 {
		return true
	}
	if !sameURL(page.FinalURL, requestedURL) {
		return !hasLoginForm(page)
	}
	semantic := strings.ToLower(strings.Join(elementTexts(page.Elements), " ") + " " + page.Title)
	return strings.Contains(semantic, "not found") || strings.Contains(semantic, "does not exist")
}

func sameURLOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func nonEmptyStrings(values ...string) []string {
	result := []string{}
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func allObjectsCleaned(objects []testsmodel.OwnedObject) bool {
	if len(objects) == 0 {
		return false
	}
	for _, object := range objects {
		if object.CleanupStatus != "verified" {
			return false
		}
	}
	return true
}
