package coretests

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type SelectionOptions struct {
	MaxCandidates int
}

type featureReference struct {
	ID        string
	Name      string
	Type      string
	EntityIDs []string
}

func SelectCandidates(
	application *model.Application,
	runtime *runtimeverify.Runtime,
	options SelectionOptions,
) ([]testsmodel.TestCase, error) {
	if options.MaxCandidates <= 0 {
		options.MaxCandidates = 20
	}
	interfaces := make(map[string]surface.Interface, len(application.Surface.Interfaces))
	for _, item := range application.Surface.Interfaces {
		interfaces[item.ID] = item
	}
	featureByInterface := indexFeatures(application.Features)
	entityCentrality := entityCentrality(application)
	observations := indexObservations(runtime.Interfaces)
	candidates := map[string]testsmodel.TestCase{}

	loginInterfaceID := canonicalLoginInterface(application, runtime)
	if loginInterfaceID != "" {
		item := interfaces[loginInterfaceID]
		if observation, ok := findObservation(observations[loginInterfaceID], "unauthenticated", runtimeverify.StatusVerified); ok {
			candidate := readCandidate(item, featureByInterface[item.ID], observation, "public")
			candidate.ID = item.ID + ".public"
			candidate.Name = item.Name + " Is Publicly Available"
			candidate.Description = "Verify the canonical login surface is reachable without an authenticated session."
			candidate.Assertions = append(candidate.Assertions, testsmodel.Assertion{Type: "not_authenticated"})
			candidate.Safety.SelectionScore = 1000
			candidate.Safety.SelectionReasons = append(candidate.Safety.SelectionReasons, "canonical public login surface")
			candidates[candidate.ID] = candidate
		}
		if runtime.Authentication.Status == runtimeverify.StatusVerified {
			candidate := testsmodel.TestCase{
				ID: loginInterfaceID + ".success", Name: "Authenticate With Configured Identity",
				Kind:            testsmodel.KindCore,
				Description:     "Verify the configured identity can establish an authenticated browser session.",
				FeatureIDs:      referencesIDs(featureByInterface[loginInterfaceID]),
				InterfaceIDs:    []string{loginInterfaceID},
				EntityIDs:       referencesEntities(featureByInterface[loginInterfaceID]),
				Preconditions:   testsmodel.Preconditions{Authentication: "authenticated"},
				GeneratedValues: []testsmodel.ValueReference{},
				Steps:           []testsmodel.Step{{Type: "observe"}},
				Assertions:      []testsmodel.Assertion{{Type: "authenticated"}},
				Cleanup:         []testsmodel.CleanupStep{},
				Safety: testsmodel.SafetyMetadata{
					Classification: "safe", SelectionScore: 990,
					SelectionReasons: []string{"runtime-verified authentication", "onboarding identity"},
				},
				EvidenceIDs: append([]string(nil), runtime.Authentication.EvidenceIDs...),
			}
			candidates[candidate.ID] = candidate
		}
	}

	protected := make([]testsmodel.TestCase, 0)
	for interfaceID, stateObservations := range observations {
		item, ok := interfaces[interfaceID]
		if !ok || runtimeverify.ClassifyInterface(item).Safety != runtimeverify.SafetySafe {
			continue
		}
		if observation, ok := findObservation(stateObservations, "authenticated", runtimeverify.StatusVerified); ok {
			candidate := readCandidate(item, featureByInterface[item.ID], observation, "authenticated")
			candidate.ID = item.ID + ".authenticated"
			candidate.Name = displayName(item) + " Authenticated View"
			candidate.Preconditions.Authentication = "authenticated"
			candidate.Assertions = append(candidate.Assertions, testsmodel.Assertion{Type: "authenticated"})
			candidate.Safety.SelectionScore = 800 + centralityScore(item.EntityIDs, entityCentrality)
			candidate.Safety.SelectionReasons = append(candidate.Safety.SelectionReasons, "runtime-verified authenticated page")
			candidates[candidate.ID] = candidate
		}
		if observation, ok := findObservation(stateObservations, "unauthenticated", runtimeverify.StatusAuthRequired); ok {
			candidate := readCandidate(item, featureByInterface[item.ID], observation, "access_control")
			candidate.ID = item.ID + ".access_control"
			candidate.Name = displayName(item) + " Requires Authentication"
			candidate.Description = "Verify anonymous navigation is intercepted by the canonical login surface."
			candidate.Assertions = []testsmodel.Assertion{{Type: "not_authenticated"}}
			if observation.FinalURL != "" {
				candidate.Assertions = append(candidate.Assertions, testsmodel.Assertion{
					Type: "url_matches", Expected: observation.FinalURL,
				})
			}
			candidate.Safety.SelectionScore = 900 + centralityScore(item.EntityIDs, entityCentrality)
			candidate.Safety.SelectionReasons = append(candidate.Safety.SelectionReasons, "runtime-verified authentication boundary")
			protected = append(protected, candidate)
		}
	}
	// One representative boundary test is enough for the initial Core pack;
	// state-specific coverage for every selected page remains in runtime.json.
	sortCandidates(protected)
	if len(protected) > 0 {
		candidates[protected[0].ID] = protected[0]
	}

	for _, node := range flattenFeatures(application.Features) {
		if node.Type != "action" {
			continue
		}
		mutatingInterfaces := make([]surface.Interface, 0)
		browserActions := make([]surface.Interface, 0)
		for _, interfaceID := range node.InterfaceIDs {
			item, ok := interfaces[interfaceID]
			if ok && runtimeverify.ClassifyInterface(item).Safety == runtimeverify.SafetyMutating {
				mutatingInterfaces = append(mutatingInterfaces, item)
				if item.Type == "form_action" && item.Locator.Path != "" {
					browserActions = append(browserActions, item)
				}
			}
		}
		// The initial executor is browser-oriented. API-only mutation actions
		// remain canonical features, but are not proposed as executable browser
		// candidates without an API step model.
		if len(browserActions) == 0 {
			continue
		}
		sort.Slice(mutatingInterfaces, func(i, j int) bool { return mutatingInterfaces[i].ID < mutatingInterfaces[j].ID })
		sort.Slice(browserActions, func(i, j int) bool { return browserActions[i].ID < browserActions[j].ID })
		interfaceIDs := make([]string, 0, len(mutatingInterfaces))
		entityIDs := append([]string(nil), node.EntityIDs...)
		for _, item := range mutatingInterfaces {
			interfaceIDs = append(interfaceIDs, item.ID)
			entityIDs = append(entityIDs, item.EntityIDs...)
		}
		score := 450 + centralityScore(entityIDs, entityCentrality)
		reasons := []string{"action node", "concrete mutating interface", "owned test data required"}
		semantic := strings.ToLower(node.ID + " " + node.Name)
		switch {
		case containsAny(semantic, "create"):
			score += 100
			reasons = append(reasons, "core creation operation")
		case containsAny(semantic, "add"):
			score += 80
			reasons = append(reasons, "core addition operation")
		case containsAny(semantic, "update", "move"):
			score += 70
			reasons = append(reasons, "core update operation")
		case containsAny(semantic, "delete", "remove"):
			score += 40
			reasons = append(reasons, "core removal operation")
		}
		if len(mutatingInterfaces) > 1 {
			interfaceBonus := (len(mutatingInterfaces) - 1) * 5
			if interfaceBonus > 20 {
				interfaceBonus = 20
			}
			score += interfaceBonus
			reasons = append(reasons, "multiple concrete invocation points")
		}
		if containsAny(semantic, "create", "add", "update", "move", "delete", "remove") {
			reasons = append(reasons, "core lifecycle operation")
		}
		ownedReference := "created." + firstOr(entityIDs, "entity")
		generatedReference := "generated." + firstOr(entityIDs, "entity") + ".name"
		candidate := testsmodel.TestCase{
			ID: node.ID, Name: node.Name, Kind: testsmodel.KindCore,
			Description: node.Description, FeatureIDs: []string{node.ID},
			InterfaceIDs: interfaceIDs, EntityIDs: entityIDs,
			Preconditions: testsmodel.Preconditions{Authentication: node.Access.Authentication},
			GeneratedValues: []testsmodel.ValueReference{{
				Reference: generatedReference, Generated: "unique_name", Prefix: "Noescope Test",
			}},
			Steps:      []testsmodel.Step{{Type: "submit", InterfaceID: browserActions[0].ID}, {Type: "observe"}},
			Assertions: []testsmodel.Assertion{{Type: "entity_visible", Expected: node.Name}},
			Cleanup:    []testsmodel.CleanupStep{{Type: "delete_created_entity", OwnedReference: ownedReference}},
			Safety: testsmodel.SafetyMetadata{
				Classification: "mutating", Mutating: true, RequiresOwnedData: true,
				CleanupRequired: true, SelectionScore: score, SelectionReasons: reasons,
			},
			EvidenceIDs: append([]string(nil), node.EvidenceIDs...),
		}
		candidates[candidate.ID] = candidate
	}

	result := make([]testsmodel.TestCase, 0, len(candidates))
	for _, candidate := range candidates {
		testsmodel.NormalizeTest(&candidate)
		if err := testsmodel.ValidateTest(candidate, application); err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	sortCandidates(result)
	if len(result) > options.MaxCandidates {
		result = result[:options.MaxCandidates]
	}
	return result, nil
}

func readCandidate(item surface.Interface, references []featureReference, observation runtimeverify.InterfaceObservation, suffix string) testsmodel.TestCase {
	assertions := []testsmodel.Assertion{}
	if observation.HTTPStatus != 0 {
		assertions = append(assertions, testsmodel.Assertion{Type: "http_status", HTTPStatus: observation.HTTPStatus})
	}
	if observation.Title != "" {
		if grounded := GroundSafeString(observation.Title); grounded.Usable {
			assertions = append(assertions, testsmodel.Assertion{
				Type: "page_title", Match: grounded.Match, Expected: grounded.Value,
			})
		}
	}
	return testsmodel.TestCase{
		ID: item.ID + "." + suffix, Name: displayName(item), Kind: testsmodel.KindCore,
		Description: "Verify the canonical read-only interface behaves as observed during onboarding.",
		FeatureIDs:  referencesIDs(references), InterfaceIDs: []string{item.ID},
		EntityIDs:       append(append([]string(nil), item.EntityIDs...), referencesEntities(references)...),
		Preconditions:   testsmodel.Preconditions{Authentication: "unauthenticated"},
		GeneratedValues: []testsmodel.ValueReference{},
		Steps:           []testsmodel.Step{{Type: "navigate", InterfaceID: item.ID}, {Type: "observe"}},
		Assertions:      assertions, Cleanup: []testsmodel.CleanupStep{},
		Safety: testsmodel.SafetyMetadata{
			Classification: "safe", SelectionReasons: []string{"concrete browser interface"},
		},
		EvidenceIDs: append([]string(nil), observation.EvidenceIDs...),
	}
}

func sortCandidates(candidates []testsmodel.TestCase) {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Safety.SelectionScore != candidates[j].Safety.SelectionScore {
			return candidates[i].Safety.SelectionScore > candidates[j].Safety.SelectionScore
		}
		return candidates[i].ID < candidates[j].ID
	})
}

func indexObservations(values []runtimeverify.InterfaceObservation) map[string][]runtimeverify.InterfaceObservation {
	result := map[string][]runtimeverify.InterfaceObservation{}
	for _, value := range values {
		if value.State != "not_attempted" {
			result[value.InterfaceID] = append(result[value.InterfaceID], value)
		}
	}
	return result
}

func findObservation(values []runtimeverify.InterfaceObservation, state string, status runtimeverify.Status) (runtimeverify.InterfaceObservation, bool) {
	for _, value := range values {
		if value.State == state && value.Status == status {
			return value, true
		}
	}
	return runtimeverify.InterfaceObservation{}, false
}

func indexFeatures(nodes []features.Node) map[string][]featureReference {
	result := map[string][]featureReference{}
	for _, node := range flattenFeatures(nodes) {
		for _, interfaceID := range node.InterfaceIDs {
			result[interfaceID] = append(result[interfaceID], featureReference{
				ID: node.ID, Name: node.Name, Type: node.Type, EntityIDs: append([]string(nil), node.EntityIDs...),
			})
		}
	}
	for id := range result {
		sort.Slice(result[id], func(i, j int) bool {
			if result[id][i].Type != result[id][j].Type {
				return result[id][i].Type == "action"
			}
			return result[id][i].ID < result[id][j].ID
		})
	}
	return result
}

func flattenFeatures(nodes []features.Node) []features.Node {
	result := []features.Node{}
	var walk func(features.Node)
	walk = func(node features.Node) {
		result = append(result, node)
		for _, child := range node.Children {
			walk(child)
		}
	}
	for _, node := range nodes {
		walk(node)
	}
	return result
}

func entityCentrality(application *model.Application) map[string]int {
	result := map[string]int{}
	for _, item := range application.Surface.Interfaces {
		for _, id := range item.EntityIDs {
			result[id]++
		}
	}
	for _, node := range flattenFeatures(application.Features) {
		for _, id := range node.EntityIDs {
			result[id]++
		}
	}
	return result
}

func centralityScore(ids []string, centrality map[string]int) int {
	total := 0
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		total += centrality[id]
	}
	// Centrality is intentionally bounded below the read-only candidate band,
	// while still differentiating core aggregate entities from incidental ones.
	score := total / 2
	if score > 160 {
		return 160
	}
	return score
}

func canonicalLoginInterface(application *model.Application, runtime *runtimeverify.Runtime) string {
	loginURL := strings.TrimRight(runtime.Authentication.LoginURL, "/")
	ids := []string{}
	for _, item := range application.Surface.Interfaces {
		if item.Type != "web_page" {
			continue
		}
		semantic := strings.ToLower(item.ID + " " + item.Name + " " + item.Description)
		if !containsAny(semantic, "login", "sign in", "signin") {
			continue
		}
		if loginURL != "" && !strings.HasSuffix(loginURL, strings.TrimRight(item.Locator.Path, "/")) {
			continue
		}
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func referencesIDs(values []featureReference) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.ID)
	}
	return result
}

func referencesEntities(values []featureReference) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.EntityIDs...)
	}
	return result
}

func displayName(item surface.Interface) string {
	if item.Name != "" {
		return item.Name
	}
	return item.ID
}

func containsAny(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func firstOr(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	return values[0]
}

func candidateLabel(candidate testsmodel.TestCase) string {
	return fmt.Sprintf("%s score=%d", candidate.ID, candidate.Safety.SelectionScore)
}
