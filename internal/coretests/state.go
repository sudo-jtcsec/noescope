package coretests

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type ExecutionState struct {
	executionID string
	testID      string
	values      map[string]string
	owned       map[string]testsmodel.OwnedObject
}

func NewExecutionState() *ExecutionState {
	return NewExecutionStateFor("", "")

}

func NewExecutionStateFor(executionID, testID string) *ExecutionState {
	return &ExecutionState{
		executionID: executionID, testID: testID,
		values: map[string]string{}, owned: map[string]testsmodel.OwnedObject{},
	}
}

func (s *ExecutionState) ResolveValue(reference string, value testsmodel.ValueReference) (string, error) {
	key := reference
	if key == "" {
		key = value.Reference
	}
	if key == "" {
		return "", fmt.Errorf("generated value requires a semantic reference")
	}
	if existing, ok := s.values[key]; ok {
		return existing, nil
	}
	if value.Generated != "unique_name" {
		return "", fmt.Errorf("unsupported generated value %q", value.Generated)
	}
	prefix := strings.TrimSpace(value.Prefix)
	if prefix == "" {
		prefix = "Noescope Test"
	}
	generated := prefix + " " + id.New("")
	s.values[key] = generated
	return generated, nil
}

func (s *ExecutionState) TrackOwned(reference, objectID string) error {
	return s.EstablishOwned(reference, "", objectID, nil, nil)
}

func (s *ExecutionState) EstablishOwned(
	reference, entityID, objectID string,
	generatedFields map[string]string,
	evidenceIDs []string,
) error {
	if reference == "" || objectID == "" {
		return fmt.Errorf("owned object requires a reference and runtime object ID")
	}
	fields := make(map[string]string, len(generatedFields))
	for key, value := range generatedFields {
		fields[key] = value
	}
	s.owned[reference] = testsmodel.OwnedObject{
		OwnershipID: id.New("ownership"), ExecutionID: s.executionID,
		EntityID: entityID, CreatedByTestID: s.testID,
		RuntimeIdentifier: objectID, GeneratedFields: fields,
		CreationEvidenceIDs: append([]string(nil), evidenceIDs...),
	}
	return nil
}

func (s *ExecutionState) RequireOwned(reference string) (string, error) {
	object, ok := s.owned[reference]
	if !ok || object.RuntimeIdentifier == "" {
		return "", fmt.Errorf("refusing cleanup: object %q is not owned by this test execution", reference)
	}
	if object.ExecutionID != s.executionID || object.CreatedByTestID != s.testID {
		return "", fmt.Errorf("refusing cleanup: object %q belongs to a different test execution", reference)
	}
	return object.RuntimeIdentifier, nil
}

func (s *ExecutionState) Owns(reference string) bool {
	object, ok := s.owned[reference]
	return ok && object.RuntimeIdentifier != "" &&
		object.ExecutionID == s.executionID && object.CreatedByTestID == s.testID
}

func (s *ExecutionState) MarkCleanup(reference, status string, evidenceIDs []string) error {
	if _, err := s.RequireOwned(reference); err != nil {
		return err
	}
	object := s.owned[reference]
	object.CleanupStatus = status
	object.CleanupEvidenceIDs = append([]string(nil), evidenceIDs...)
	s.owned[reference] = object
	return nil
}

func (s *ExecutionState) UpdateOwnedFields(reference string, fields map[string]string) error {
	if _, err := s.RequireOwned(reference); err != nil {
		return err
	}
	object := s.owned[reference]
	if object.GeneratedFields == nil {
		object.GeneratedFields = map[string]string{}
	}
	for key, value := range fields {
		object.GeneratedFields[key] = value
	}
	s.owned[reference] = object
	return nil
}

func (s *ExecutionState) OwnedObjects() []testsmodel.OwnedObject {
	result := make([]testsmodel.OwnedObject, 0, len(s.owned))
	for _, object := range s.owned {
		object.GeneratedFields = cloneStrings(object.GeneratedFields)
		result = append(result, object)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].EntityID != result[j].EntityID {
			return result[i].EntityID < result[j].EntityID
		}
		return result[i].RuntimeIdentifier < result[j].RuntimeIdentifier
	})
	return result
}

func (s *ExecutionState) Values() map[string]string {
	result := make(map[string]string, len(s.values))
	for key, value := range s.values {
		result[key] = value
	}
	return result
}

func cloneStrings(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

// GuardCleanup enforces the ownership boundary before a destructive cleanup
// step can be passed to a concrete executor.
func GuardCleanup(step testsmodel.CleanupStep, state *ExecutionState) (string, error) {
	if step.Type != "delete_created_entity" {
		return "", nil
	}
	if state == nil {
		return "", fmt.Errorf("refusing cleanup: execution ownership state is unavailable")
	}
	return state.RequireOwned(step.OwnedReference)
}
