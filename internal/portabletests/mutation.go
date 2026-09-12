package portabletests

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

type portableState struct {
	executionID string
	testID      string
	values      map[string]string
	owned       map[string]OwnedObject
	bindings    map[string]string
}

func (r *Runner) runMutating(
	ctx context.Context,
	executionID, baseURL string,
	test Test,
	engine browser.MutationEngine,
	page browser.Page,
	_ IdentityReference,
	credentials browser.Credentials,
) Result {
	result := Result{TestID: test.ID, Mutating: true, Status: StatusFailed, EvidenceIDs: []string{}, OwnedObjects: []OwnedObject{}}
	state := &portableState{executionID: executionID, testID: test.ID, values: map[string]string{}, owned: map[string]OwnedObject{}, bindings: map[string]string{}}
	for _, declaration := range test.GeneratedValues {
		prefix := strings.TrimSpace(declaration.Prefix)
		if prefix == "" {
			prefix = "Noescope Test"
		}
		state.values[declaration.Reference] = prefix + " " + newSuffix()
	}
	var pending *browser.FormSubmission
	var lastValueReference string
	workflowErr := func() error {
		for _, step := range test.Steps {
			switch step.Type {
			case "navigate":
				item, ok := portableInterface(test, step.InterfaceID)
				if !ok {
					return fmt.Errorf("missing interface binding %q", step.InterfaceID)
				}
				target, err := resolveURL(baseURL, item.Path, state.bindings)
				if err != nil {
					return err
				}
				page, err = engine.Navigate(ctx, target)
				if err != nil {
					return err
				}
				pending = nil
			case "fill":
				if step.Value == nil {
					return fmt.Errorf("fill step lacks a generated value")
				}
				value := state.values[step.Value.Reference]
				if value == "" {
					return fmt.Errorf("generated value %q is unavailable", step.Value.Reference)
				}
				form, control, err := bindPortableFormControl(page, semanticTerms(step.Field))
				if err != nil {
					return err
				}
				pending = &browser.FormSubmission{PageURL: page.FinalURL, FormSelector: form.Selector,
					SubmitSelector: form.SubmitSelector, Entries: []browser.FormEntry{{Selector: control.Selector, Type: control.Type, Value: value}}}
				lastValueReference = step.Value.Reference
			case "submit":
				if pending == nil {
					return fmt.Errorf("submit step has no safely bound live form")
				}
				var err error
				page, err = engine.SubmitForm(ctx, *pending)
				pending = nil
				if err != nil {
					return err
				}
			case "wait_for":
				if !strings.HasPrefix(step.Target, "created.") {
					return fmt.Errorf("unsupported mutating wait target %q", step.Target)
				}
				entityID := strings.TrimPrefix(step.Target, "created.")
				assertion, item, ok := ownershipAssertion(test, entityID, lastValueReference)
				if !ok || !pageContains(page, state.values[assertion.Expected]) {
					return fmt.Errorf("%s creation was not confirmed by the resulting page", entityID)
				}
				parameter := routeParameterForEntity(item.Path, entityID)
				runtimeID, err := capturePortableBinding(page, baseURL, item.Path, parameter, state.values[assertion.Expected])
				if err != nil {
					return fmt.Errorf("capture %s identifier: %w", entityID, err)
				}
				state.bindings[parameter] = runtimeID
				state.owned[step.Target] = OwnedObject{OwnershipID: "ownership_" + newSuffix(), ExecutionID: executionID,
					EntityID: entityID, TestID: test.ID, RuntimeIdentifier: runtimeID,
					GeneratedFields: map[string]string{fieldName(lastValueReference): state.values[lastValueReference]}}
			case "observe":
				for _, assertion := range test.Assertions {
					if assertion.Expected == lastValueReference && !pageContains(page, state.values[assertion.Expected]) {
						return fmt.Errorf("updated entity value was not observed")
					}
				}
			default:
				return fmt.Errorf("unsupported portable mutating step %q", step.Type)
			}
		}
		return nil
	}()
	if workflowErr != nil {
		result.WorkflowFailure = r.sanitize(workflowErr.Error(), credentials)
	}
	cleanupErr := cleanupPortable(ctx, baseURL, test, engine, state)
	result.OwnedObjects = ownedObjects(state)
	if cleanupErr != nil {
		result.Status = StatusCleanupFailed
		result.CleanupFailure = r.sanitize(cleanupErr.Error(), credentials)
		result.Reason = result.CleanupFailure
		if result.WorkflowFailure != "" {
			result.Reason = result.WorkflowFailure + "; cleanup failed: " + result.CleanupFailure
		}
		return result
	}
	if workflowErr != nil {
		result.Status, result.Reason = StatusFailed, result.WorkflowFailure
		return result
	}
	if len(state.owned) == 0 || !allPortableCleaned(state) {
		result.Status, result.Reason = StatusCleanupFailed, "owned objects were not all verified cleaned"
		result.CleanupFailure = result.Reason
		return result
	}
	result.Status = StatusPassed
	return result
}

func bindPortableFormControl(page browser.Page, terms []string) (browser.Form, browser.FormControl, error) {
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
			haystack := strings.ToLower(control.Name + " " + control.ID + " " + control.Label)
			score := 0
			for index, term := range terms {
				if strings.EqualFold(control.Name, term) || strings.EqualFold(control.ID, term) {
					score = 100 - index
					break
				}
				if strings.Contains(haystack, strings.ToLower(term)) && score < 50-index {
					score = 50 - index
				}
			}
			if score > 0 {
				matches = append(matches, match{form, control, score})
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

func cleanupPortable(ctx context.Context, baseURL string, test Test, engine browser.MutationEngine, state *portableState) error {
	failures := []string{}
	for _, step := range test.Cleanup {
		owned, ok := state.owned[step.OwnedReference]
		if !ok {
			continue
		}
		if owned.ExecutionID != state.executionID || owned.TestID != state.testID {
			failures = append(failures, "refusing cleanup: ownership belongs to a different execution")
			continue
		}
		item, ok := portableInterface(test, step.InterfaceID)
		if !ok {
			failures = append(failures, "cleanup interface binding is unavailable")
			continue
		}
		target, err := resolveURL(baseURL, item.Path, state.bindings)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		page, err := engine.Navigate(ctx, target)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		activation, err := portableDestructiveConfirmation(page)
		if err != nil {
			owned.CleanupStatus = "failed"
			state.owned[step.OwnedReference] = owned
			failures = append(failures, err.Error())
			continue
		}
		if _, err = engine.Activate(ctx, activation); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		view, ok := ownershipView(test, owned.EntityID)
		if !ok {
			failures = append(failures, "cleanup verification interface is unavailable")
			continue
		}
		viewURL, err := resolveURL(baseURL, view.Path, state.bindings)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		verification, err := engine.Navigate(ctx, viewURL)
		if err != nil || !portableUnavailable(verification, viewURL) {
			owned.CleanupStatus = "failed"
			state.owned[step.OwnedReference] = owned
			failures = append(failures, fmt.Sprintf("cleanup verification failed for owned %s %s", owned.EntityID, owned.RuntimeIdentifier))
			continue
		}
		owned.CleanupStatus = "verified"
		state.owned[step.OwnedReference] = owned
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func ownershipAssertion(test Test, entityID, expectedReference string) (Assertion, Interface, bool) {
	for _, assertion := range test.Assertions {
		if assertion.Type != "entity_visible" || assertion.Expected != expectedReference {
			continue
		}
		item, ok := portableInterface(test, assertion.InterfaceID)
		if ok && contains(item.EntityIDs, entityID) && routeParameterForEntity(item.Path, entityID) != "" {
			return assertion, item, true
		}
	}
	return Assertion{}, Interface{}, false
}

func ownershipView(test Test, entityID string) (Interface, bool) {
	for _, assertion := range test.Assertions {
		item, ok := portableInterface(test, assertion.InterfaceID)
		if ok && contains(item.EntityIDs, entityID) && routeParameterForEntity(item.Path, entityID) != "" {
			return item, true
		}
	}
	return Interface{}, false
}

func capturePortableBinding(page browser.Page, baseURL, template, parameter, expectedText string) (string, error) {
	candidates := []browser.Link{{URL: page.FinalURL, Text: strings.Join(portableElementTexts(page.Elements), " ")}}
	candidates = append(candidates, page.Links...)
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	for _, candidate := range candidates {
		if candidate.URL == "" || candidate.URL != page.FinalURL && !strings.Contains(strings.ToLower(candidate.Text), strings.ToLower(expectedText)) {
			continue
		}
		parsed, err := url.Parse(candidate.URL)
		if err != nil || parsed.Scheme != base.Scheme || parsed.Host != base.Host {
			continue
		}
		bindings, ok := matchPortableTemplate(template, parsed.Path)
		if ok && bindings[parameter] != "" {
			return bindings[parameter], nil
		}
	}
	return "", fmt.Errorf("no same-origin canonical route observation supplied %q", parameter)
}

func matchPortableTemplate(template, observed string) (map[string]string, bool) {
	want, got := strings.Split(strings.Trim(template, "/"), "/"), strings.Split(strings.Trim(observed, "/"), "/")
	if len(want) != len(got) {
		return nil, false
	}
	bindings := map[string]string{}
	for index, part := range want {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			value, err := url.PathUnescape(got[index])
			if err != nil || value == "" {
				return nil, false
			}
			bindings[strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")] = value
		} else if part != got[index] {
			return nil, false
		}
	}
	return bindings, true
}

func portableDestructiveConfirmation(page browser.Page) (browser.Activation, error) {
	for _, wanted := range []string{"yes", "confirm", "delete", "remove"} {
		for _, link := range page.Links {
			if strings.TrimSpace(strings.ToLower(link.Text)) == wanted && link.Selector != "" {
				return browser.Activation{PageURL: page.FinalURL, Selector: link.Selector, Label: link.Text}, nil
			}
		}
	}
	return browser.Activation{}, fmt.Errorf("no deterministic destructive confirmation control was observed")
}

func portableUnavailable(page browser.Page, requested string) bool {
	if page.HTTPStatus == 404 || page.HTTPStatus == 410 {
		return true
	}
	if !sameURL(page.FinalURL, requested) {
		return !hasLoginForm(page)
	}
	semantic := strings.ToLower(strings.Join(portableElementTexts(page.Elements), " ") + " " + page.Title)
	return strings.Contains(semantic, "not found") || strings.Contains(semantic, "does not exist")
}

func routeParameterForEntity(path, entityID string) string {
	for _, name := range routeParameters(path) {
		if strings.TrimSuffix(strings.ToLower(name), "_id") == strings.ToLower(entityID) {
			return name
		}
	}
	return ""
}

func routeParameters(path string) []string {
	result := []string{}
	for {
		start := strings.Index(path, "{")
		if start < 0 {
			return result
		}
		end := strings.Index(path[start+1:], "}")
		if end < 0 {
			return result
		}
		result = append(result, path[start+1:start+1+end])
		path = path[start+end+2:]
	}
}

func semanticTerms(field string) []string {
	parts := strings.FieldsFunc(field, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
	result := make([]string, 0, len(parts))
	for index := len(parts) - 1; index >= 0; index-- {
		result = append(result, parts[index])
	}
	return result
}

func fieldName(reference string) string {
	parts := strings.Split(reference, ".")
	return parts[len(parts)-1]
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func portableElementTexts(elements []browser.Element) []string {
	result := make([]string, 0, len(elements))
	for _, element := range elements {
		result = append(result, element.Name+" "+element.Text)
	}
	return result
}

func ownedObjects(state *portableState) []OwnedObject {
	result := make([]OwnedObject, 0, len(state.owned))
	for _, object := range state.owned {
		result = append(result, object)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].EntityID < result[j].EntityID })
	return result
}

func allPortableCleaned(state *portableState) bool {
	for _, object := range state.owned {
		if object.CleanupStatus != "verified" {
			return false
		}
	}
	return len(state.owned) > 0
}
