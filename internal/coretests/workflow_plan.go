package coretests

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type OwnedLifecyclePlan struct {
	Test testsmodel.TestCase

	ParentEntity entities.Entity
	ChildEntity  entities.Entity

	ParentCreate string
	ParentView   string
	ChildCreate  string
	ChildView    string
	ChildEdit    string
	ChildUpdate  string
	ChildRemove  string
	ParentRemove string

	ParentParameter string
	ChildParameter  string
	ParentValueRef  string
	ChildValueRef   string
	UpdatedValueRef string
}

type workflowBinding struct {
	FeatureID   string
	InterfaceID string
	Score       int
}

func FilterTestCandidates(
	candidates []testsmodel.TestCase,
	workflow *OwnedLifecyclePlan,
	testID string,
) ([]testsmodel.TestCase, error) {
	if testID == "" {
		return candidates, nil
	}
	for _, candidate := range candidates {
		if candidate.ID == testID {
			return []testsmodel.TestCase{candidate}, nil
		}
	}
	if workflow != nil && workflow.Test.ID == testID {
		return []testsmodel.TestCase{workflow.Test}, nil
	}
	return nil, fmt.Errorf("Core Test candidate %q was not found", testID)
}

// PlanOwnedLifecycle deterministically finds one parent/child business
// lifecycle from canonical entities, features, and browser interfaces.
func PlanOwnedLifecycle(application *model.Application) (*OwnedLifecyclePlan, error) {
	interfaces := make(map[string]surface.Interface, len(application.Surface.Interfaces))
	for _, item := range application.Surface.Interfaces {
		interfaces[item.ID] = item
	}
	nodes := flattenFeatures(application.Features)
	centrality := entityCentrality(application)
	entitiesByID := make(map[string]entities.Entity, len(application.Entities))
	for _, entity := range application.Entities {
		entitiesByID[entity.ID] = entity
	}

	type candidate struct {
		plan  *OwnedLifecyclePlan
		score int
	}
	candidates := []candidate{}
	for _, parent := range application.Entities {
		for _, relationship := range parent.Relationships {
			if relationship.Type != "has_many" {
				continue
			}
			child, ok := entitiesByID[relationship.TargetEntityID]
			if !ok || !belongsTo(child, parent.ID) {
				continue
			}
			plan, score, ok := planEntityPair(parent, child, nodes, interfaces)
			if ok {
				candidates = append(candidates, candidate{
					plan: plan, score: score + centrality[parent.ID] + centrality[child.ID],
				})
			}
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no canonical parent/child lifecycle has complete browser create, update, view, and cleanup interfaces")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].plan.Test.ID < candidates[j].plan.Test.ID
	})
	return candidates[0].plan, nil
}

func planEntityPair(
	parent, child entities.Entity,
	nodes []features.Node,
	interfaces map[string]surface.Interface,
) (*OwnedLifecyclePlan, int, bool) {
	parentCreate, ok := chooseWorkflowBinding(nodes, interfaces, []string{parent.ID}, []string{"create"}, func(item surface.Interface) bool {
		return browserRoute(item) && !strings.Contains(item.Locator.Path, "{")
	})
	if !ok {
		return nil, 0, false
	}
	parentView, ok := chooseWorkflowBinding(nodes, interfaces, []string{parent.ID}, []string{"view", "show", "overview"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, parent.ID)
		return item.Type == "web_page" && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter) &&
			routeEndsWithParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}
	childCreate, ok := chooseWorkflowBinding(nodes, interfaces, []string{parent.ID, child.ID}, []string{"create"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, parent.ID)
		return browserRoute(item) && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter) &&
			routeParameterForEntity(item.Locator.Path, child.ID) == ""
	})
	if !ok {
		return nil, 0, false
	}
	childView, ok := chooseWorkflowBinding(nodes, interfaces, []string{child.ID}, []string{"view", "show", "details"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, child.ID)
		return item.Type == "web_page" && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter) &&
			routeEndsWithParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}
	childEdit, ok := chooseWorkflowBinding(nodes, interfaces, []string{child.ID}, []string{"edit"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, child.ID)
		return item.Type == "web_page" && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}
	childUpdate, ok := chooseWorkflowBinding(nodes, interfaces, []string{child.ID}, []string{"update", "save"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, child.ID)
		return browserRoute(item) && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}
	childRemove, ok := chooseWorkflowBinding(nodes, interfaces, []string{child.ID}, []string{"remove", "delete"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, child.ID)
		return browserRoute(item) && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}
	parentRemove, ok := chooseWorkflowBinding(nodes, interfaces, []string{parent.ID}, []string{"remove", "delete"}, func(item surface.Interface) bool {
		parameter := routeParameterForEntity(item.Locator.Path, parent.ID)
		return browserRoute(item) && parameter != "" && hasOnlyRouteParameter(item.Locator.Path, parameter)
	})
	if !ok {
		return nil, 0, false
	}

	featureIDs := sortedUnique([]string{
		parentCreate.FeatureID, parentView.FeatureID, childCreate.FeatureID, childView.FeatureID,
		childEdit.FeatureID, childUpdate.FeatureID, childRemove.FeatureID, parentRemove.FeatureID,
	})
	interfaceIDs := sortedUnique([]string{
		parentCreate.InterfaceID, parentView.InterfaceID, childCreate.InterfaceID, childView.InterfaceID,
		childEdit.InterfaceID, childUpdate.InterfaceID, childRemove.InterfaceID, parentRemove.InterfaceID,
	})
	parentValueRef := "generated." + parent.ID + "_name"
	childValueRef := "generated." + child.ID + "_title"
	updatedValueRef := "generated." + child.ID + "_updated_title"
	parentOwned := "created." + parent.ID
	childOwned := "created." + child.ID
	test := testsmodel.TestCase{
		ID:          "core." + parent.ID + "_" + child.ID + ".lifecycle",
		Name:        parent.Name + " and " + child.Name + " Owned Lifecycle",
		Kind:        testsmodel.KindCore,
		Description: "Create an owned parent and child, update the child, and verify dependency-ordered cleanup.",
		FeatureIDs:  featureIDs, InterfaceIDs: interfaceIDs, EntityIDs: []string{parent.ID, child.ID},
		Preconditions: testsmodel.Preconditions{Authentication: "authenticated"},
		GeneratedValues: []testsmodel.ValueReference{
			{Reference: parentValueRef, Generated: "unique_name", Prefix: "Noescope Test " + parent.Name},
			{Reference: childValueRef, Generated: "unique_name", Prefix: "Noescope Test " + child.Name},
			{Reference: updatedValueRef, Generated: "unique_name", Prefix: "Noescope Updated " + child.Name},
		},
		Steps: []testsmodel.Step{
			{Type: "navigate", InterfaceID: parentCreate.InterfaceID},
			{Type: "fill", Field: parent.ID + ".name", Value: &testsmodel.ValueReference{Reference: parentValueRef, Generated: "unique_name"}},
			{Type: "submit", InterfaceID: parentCreate.InterfaceID},
			{Type: "wait_for", Target: parentOwned},
			{Type: "navigate", InterfaceID: childCreate.InterfaceID},
			{Type: "fill", Field: child.ID + ".title", Value: &testsmodel.ValueReference{Reference: childValueRef, Generated: "unique_name"}},
			{Type: "submit", InterfaceID: childCreate.InterfaceID},
			{Type: "wait_for", Target: childOwned},
			{Type: "navigate", InterfaceID: childEdit.InterfaceID},
			{Type: "fill", Field: child.ID + ".title", Value: &testsmodel.ValueReference{Reference: updatedValueRef, Generated: "unique_name"}},
			{Type: "submit", InterfaceID: childUpdate.InterfaceID},
			{Type: "observe", InterfaceID: childView.InterfaceID},
		},
		Assertions: []testsmodel.Assertion{
			{Type: "entity_visible", Expected: parentValueRef, InterfaceID: parentView.InterfaceID},
			{Type: "entity_visible", Expected: childValueRef, InterfaceID: childView.InterfaceID},
			{Type: "entity_visible", Expected: updatedValueRef, InterfaceID: childView.InterfaceID},
		},
		Cleanup: []testsmodel.CleanupStep{
			{Type: "delete_created_entity", InterfaceID: childRemove.InterfaceID, OwnedReference: childOwned},
			{Type: "delete_created_entity", InterfaceID: parentRemove.InterfaceID, OwnedReference: parentOwned},
		},
		Safety: testsmodel.SafetyMetadata{
			Classification: "mutating", Mutating: true, RequiresOwnedData: true, CleanupRequired: true,
			SelectionReasons: []string{"canonical parent-child relationship", "complete browser lifecycle", "owned cleanup"},
		},
		EvidenceIDs: []string{},
	}
	plan := &OwnedLifecyclePlan{
		Test: test, ParentEntity: parent, ChildEntity: child,
		ParentCreate: parentCreate.InterfaceID, ParentView: parentView.InterfaceID,
		ChildCreate: childCreate.InterfaceID, ChildView: childView.InterfaceID,
		ChildEdit: childEdit.InterfaceID, ChildUpdate: childUpdate.InterfaceID,
		ChildRemove: childRemove.InterfaceID, ParentRemove: parentRemove.InterfaceID,
		ParentParameter: routeParameterForEntity(interfaces[parentView.InterfaceID].Locator.Path, parent.ID),
		ChildParameter:  routeParameterForEntity(interfaces[childView.InterfaceID].Locator.Path, child.ID),
		ParentValueRef:  parentValueRef, ChildValueRef: childValueRef, UpdatedValueRef: updatedValueRef,
	}
	return plan, parentCreate.Score + childCreate.Score + childUpdate.Score, true
}

func chooseWorkflowBinding(
	nodes []features.Node,
	interfaces map[string]surface.Interface,
	entityIDs, terms []string,
	accept func(surface.Interface) bool,
) (workflowBinding, bool) {
	bindings := []workflowBinding{}
	for _, node := range nodes {
		if node.Type != "action" || !containsAll(node.EntityIDs, entityIDs) ||
			!containsAny(strings.ToLower(node.ID+" "+node.Name), terms...) {
			continue
		}
		for _, interfaceID := range node.InterfaceIDs {
			item, ok := interfaces[interfaceID]
			if !ok || !accept(item) {
				continue
			}
			score := int(node.Confidence*100) + int(item.Confidence*100)
			if item.Type == "form_action" {
				score += 10
			}
			// Prefer an entity's own canonical namespace over a related page
			// that happens to mention the entity at the same confidence.
			for _, entityID := range entityIDs {
				if interfaceID == entityID || strings.HasPrefix(interfaceID, entityID+".") {
					score += 30
				}
				for _, term := range terms {
					if interfaceID == entityID+"."+term {
						score += 50
					}
				}
			}
			if sameStringSet(item.EntityIDs, entityIDs) {
				score += 20
			}
			bindings = append(bindings, workflowBinding{FeatureID: node.ID, InterfaceID: interfaceID, Score: score})
		}
	}
	if len(bindings) == 0 {
		return workflowBinding{}, false
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Score != bindings[j].Score {
			return bindings[i].Score > bindings[j].Score
		}
		if bindings[i].FeatureID != bindings[j].FeatureID {
			return bindings[i].FeatureID < bindings[j].FeatureID
		}
		return bindings[i].InterfaceID < bindings[j].InterfaceID
	})
	return bindings[0], true
}

func belongsTo(child entities.Entity, parentID string) bool {
	for _, relationship := range child.Relationships {
		if relationship.Type == "belongs_to" && relationship.TargetEntityID == parentID {
			return true
		}
	}
	return false
}

func containsAll(values, wanted []string) bool {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, value := range wanted {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func browserRoute(item surface.Interface) bool {
	return (item.Type == "web_page" || item.Type == "form_action") && item.Locator.Path != ""
}

func routeParameterForEntity(path, entityID string) string {
	for _, name := range routeParameterNames(path) {
		normalized := strings.TrimSuffix(strings.ToLower(name), "_id")
		if normalized == strings.ToLower(entityID) {
			return name
		}
	}
	return ""
}

func routeParameterNames(path string) []string {
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

func hasOnlyRouteParameter(path, parameter string) bool {
	names := routeParameterNames(path)
	return len(names) == 1 && names[0] == parameter
}

func routeEndsWithParameter(path, parameter string) bool {
	return strings.HasSuffix(strings.TrimSuffix(path, "/"), "{"+parameter+"}")
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]int, len(left))
	for _, value := range left {
		values[value]++
	}
	for _, value := range right {
		values[value]--
		if values[value] < 0 {
			return false
		}
	}
	return true
}
