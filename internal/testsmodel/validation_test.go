package testsmodel

import (
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

func validationApplication() *model.Application {
	return &model.Application{
		Entities: []entities.Entity{{ID: "task"}},
		Surface:  surface.Findings{Interfaces: []surface.Interface{{ID: "web.task.show"}}},
		Features: []features.Node{{ID: "tasks", Type: "module", Children: []features.Node{{
			ID: "tasks.view", Type: "action", InterfaceIDs: []string{"web.task.show"},
		}}}},
	}
}

func validTestCase() TestCase {
	return TestCase{
		ID: "tasks.view", Name: "View Task", Kind: KindCore, Description: "View a task.",
		FeatureIDs: []string{"tasks.view"}, InterfaceIDs: []string{"web.task.show"},
		EntityIDs: []string{"task"}, Preconditions: Preconditions{Authentication: "authenticated"},
		GeneratedValues: []ValueReference{},
		Steps:           []Step{{Type: "navigate", InterfaceID: "web.task.show"}, {Type: "observe"}},
		Assertions:      []Assertion{{Type: "http_status", HTTPStatus: 200}}, Cleanup: []CleanupStep{},
		Safety: SafetyMetadata{Classification: "safe"}, EvidenceIDs: []string{},
	}
}

func TestValidateTestRejectsUnknownCanonicalReferences(t *testing.T) {
	tests := []struct {
		name string
		edit func(*TestCase)
		want string
	}{
		{"interface", func(value *TestCase) { value.InterfaceIDs = []string{"web.invented"} }, "unknown interface"},
		{"feature", func(value *TestCase) { value.FeatureIDs = []string{"tasks.invented"} }, "unknown feature"},
		{"entity", func(value *TestCase) { value.EntityIDs = []string{"invented"} }, "unknown entity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validTestCase()
			test.edit(&value)
			if err := ValidateTest(value, validationApplication()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}
}

func TestValidateTestAcceptsSemanticGeneratedFieldAndRejectsArbitraryExecution(t *testing.T) {
	value := validTestCase()
	value.Steps = append(value.Steps, Step{
		Type: "fill", Field: "task.title",
		Value: &ValueReference{Reference: "generated.task_title", Generated: "unique_name", Prefix: "Noescope Test"},
	})
	if err := ValidateTest(value, validationApplication()); err != nil {
		t.Fatal(err)
	}
	value.Steps = append(value.Steps, Step{Type: "javascript", Target: "document.body"})
	if err := ValidateTest(value, validationApplication()); err == nil {
		t.Fatal("arbitrary JavaScript step should be rejected")
	}
}

func TestValidateMutatingTestRequiresOwnershipAndCleanup(t *testing.T) {
	value := validTestCase()
	value.Safety.Mutating = true
	if err := ValidateTest(value, validationApplication()); err == nil {
		t.Fatal("mutating test without ownership and cleanup should be rejected")
	}
	value.Safety.RequiresOwnedData = true
	value.Safety.CleanupRequired = true
	value.Cleanup = []CleanupStep{{Type: "delete_created_entity", OwnedReference: "created.task"}}
	if err := ValidateTest(value, validationApplication()); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePageTitleMatchModes(t *testing.T) {
	for _, match := range []string{"", "exact", "contains", "prefix"} {
		value := validTestCase()
		value.Assertions = []Assertion{{Type: "page_title", Match: match, Expected: "Projects"}}
		if err := ValidateTest(value, validationApplication()); err != nil {
			t.Fatalf("match %q rejected: %v", match, err)
		}
	}
	value := validTestCase()
	value.Assertions = []Assertion{{Type: "page_title", Match: "regex", Expected: ".*"}}
	if err := ValidateTest(value, validationApplication()); err == nil {
		t.Fatal("regex page title assertion should be rejected")
	}
}
