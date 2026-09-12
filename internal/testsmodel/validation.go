package testsmodel

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

var semanticID = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

var stepTypes = map[string]struct{}{
	"navigate": {}, "fill": {}, "click": {}, "submit": {}, "wait_for": {}, "observe": {},
}

var assertionTypes = map[string]struct{}{
	"url_matches": {}, "page_title": {}, "element_present": {}, "text_present": {},
	"authenticated": {}, "not_authenticated": {}, "http_status": {}, "entity_visible": {},
}

var cleanupTypes = map[string]struct{}{
	"delete_created_entity": {}, "navigate": {}, "logout": {},
}

func ValidateTest(test TestCase, application *model.Application) error {
	if !semanticID.MatchString(test.ID) {
		return fmt.Errorf("test %q has invalid semantic ID", test.ID)
	}
	if test.Kind != KindCore {
		return fmt.Errorf("test %q has invalid kind %q", test.ID, test.Kind)
	}
	if test.Name == "" || test.Description == "" {
		return fmt.Errorf("test %q requires a name and description", test.ID)
	}
	features, interfaces, entities := canonicalIDs(application)
	for _, id := range test.FeatureIDs {
		if _, ok := features[id]; !ok {
			return fmt.Errorf("test %q references unknown feature ID %q", test.ID, id)
		}
	}
	for _, id := range test.InterfaceIDs {
		if _, ok := interfaces[id]; !ok {
			return fmt.Errorf("test %q references unknown interface ID %q", test.ID, id)
		}
	}
	for _, id := range test.EntityIDs {
		if _, ok := entities[id]; !ok {
			return fmt.Errorf("test %q references unknown entity ID %q", test.ID, id)
		}
	}
	if len(test.InterfaceIDs) == 0 {
		return fmt.Errorf("test %q has no canonical interface references", test.ID)
	}
	generatedReferences := map[string]struct{}{}
	for index, value := range test.GeneratedValues {
		if !semanticID.MatchString(value.Reference) || value.Generated != "unique_name" {
			return fmt.Errorf("test %q generated_values[%d] is invalid", test.ID, index)
		}
		if _, exists := generatedReferences[value.Reference]; exists {
			return fmt.Errorf("test %q duplicates generated value reference %q", test.ID, value.Reference)
		}
		generatedReferences[value.Reference] = struct{}{}
	}
	for index, step := range test.Steps {
		if _, ok := stepTypes[step.Type]; !ok {
			return fmt.Errorf("test %q step[%d] has unsupported type %q", test.ID, index, step.Type)
		}
		if step.InterfaceID != "" {
			if _, ok := interfaces[step.InterfaceID]; !ok {
				return fmt.Errorf("test %q step[%d] references unknown interface ID %q", test.ID, index, step.InterfaceID)
			}
		}
		switch step.Type {
		case "navigate":
			if step.InterfaceID == "" {
				return fmt.Errorf("test %q step[%d] navigate requires a canonical interface ID", test.ID, index)
			}
		case "fill":
			if !semanticID.MatchString(step.Field) || step.Value == nil || step.Value.Generated == "" {
				return fmt.Errorf("test %q step[%d] fill requires a semantic field and generated value", test.ID, index)
			}
		case "click", "wait_for":
			if !semanticID.MatchString(step.Target) {
				return fmt.Errorf("test %q step[%d] %s requires a semantic target", test.ID, index, step.Type)
			}
		case "submit":
			if step.InterfaceID == "" {
				return fmt.Errorf("test %q step[%d] submit requires a canonical interface ID", test.ID, index)
			}
		}
	}
	for index, assertion := range test.Assertions {
		if _, ok := assertionTypes[assertion.Type]; !ok {
			return fmt.Errorf("test %q assertion[%d] has unsupported type %q", test.ID, index, assertion.Type)
		}
		switch assertion.Type {
		case "url_matches", "page_title", "element_present", "text_present", "entity_visible":
			if assertion.Expected == "" {
				return fmt.Errorf("test %q assertion[%d] %s requires an expected value", test.ID, index, assertion.Type)
			}
		case "http_status":
			if assertion.HTTPStatus < 100 || assertion.HTTPStatus > 599 {
				return fmt.Errorf("test %q assertion[%d] has invalid HTTP status", test.ID, index)
			}
		}
		if assertion.Type == "page_title" {
			if assertion.Match != "" && assertion.Match != "exact" &&
				assertion.Match != "contains" && assertion.Match != "prefix" {
				return fmt.Errorf("test %q assertion[%d] has invalid page title match %q", test.ID, index, assertion.Match)
			}
		} else if assertion.Match != "" {
			return fmt.Errorf("test %q assertion[%d] uses match mode with unsupported assertion %q", test.ID, index, assertion.Type)
		}
		if assertion.InterfaceID != "" {
			if _, ok := interfaces[assertion.InterfaceID]; !ok {
				return fmt.Errorf("test %q assertion[%d] references unknown interface ID %q", test.ID, index, assertion.InterfaceID)
			}
		}
	}
	for index, cleanup := range test.Cleanup {
		if _, ok := cleanupTypes[cleanup.Type]; !ok {
			return fmt.Errorf("test %q cleanup[%d] has unsupported type %q", test.ID, index, cleanup.Type)
		}
		if cleanup.Type == "delete_created_entity" && cleanup.OwnedReference == "" {
			return fmt.Errorf("test %q cleanup[%d] lacks an owned object reference", test.ID, index)
		}
		if cleanup.InterfaceID != "" {
			if _, ok := interfaces[cleanup.InterfaceID]; !ok {
				return fmt.Errorf("test %q cleanup[%d] references unknown interface ID %q", test.ID, index, cleanup.InterfaceID)
			}
		}
	}
	if test.Safety.Mutating && (!test.Safety.RequiresOwnedData || !test.Safety.CleanupRequired || len(test.Cleanup) == 0) {
		return fmt.Errorf("mutating test %q requires owned test data and cleanup", test.ID)
	}
	return nil
}

func ValidatePack(pack *TestPack, application *model.Application) error {
	if pack.SchemaVersion != SchemaVersion {
		return fmt.Errorf("test pack schema version %q is incompatible", pack.SchemaVersion)
	}
	seen := make(map[string]struct{}, len(pack.Tests))
	for _, test := range pack.Tests {
		if _, exists := seen[test.ID]; exists {
			return fmt.Errorf("duplicate verified test ID %q", test.ID)
		}
		seen[test.ID] = struct{}{}
		if err := ValidateTest(test, application); err != nil {
			return err
		}
	}
	return nil
}

func NormalizeTest(test *TestCase) {
	test.FeatureIDs = sortedUnique(test.FeatureIDs)
	test.InterfaceIDs = sortedUnique(test.InterfaceIDs)
	test.EntityIDs = sortedUnique(test.EntityIDs)
	test.EvidenceIDs = sortedUnique(test.EvidenceIDs)
	test.Safety.SelectionReasons = sortedUnique(test.Safety.SelectionReasons)
	sort.Slice(test.GeneratedValues, func(i, j int) bool {
		return test.GeneratedValues[i].Reference < test.GeneratedValues[j].Reference
	})
}

func canonicalIDs(application *model.Application) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	featureIDs := map[string]struct{}{}
	var walk func(features.Node)
	walk = func(node features.Node) {
		featureIDs[node.ID] = struct{}{}
		for _, child := range node.Children {
			walk(child)
		}
	}
	for _, node := range application.Features {
		walk(node)
	}
	interfaceIDs := map[string]struct{}{}
	for _, item := range application.Surface.Interfaces {
		interfaceIDs[item.ID] = struct{}{}
	}
	entityIDs := map[string]struct{}{}
	for _, entity := range application.Entities {
		entityIDs[entity.ID] = struct{}{}
	}
	return featureIDs, interfaceIDs, entityIDs
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
