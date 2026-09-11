package coretests

import (
	"fmt"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/id"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type ExecutionState struct {
	values map[string]string
	owned  map[string]string
}

func NewExecutionState() *ExecutionState {
	return &ExecutionState{values: map[string]string{}, owned: map[string]string{}}
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
	if reference == "" || objectID == "" {
		return fmt.Errorf("owned object requires a reference and runtime object ID")
	}
	s.owned[reference] = objectID
	return nil
}

func (s *ExecutionState) RequireOwned(reference string) (string, error) {
	objectID, ok := s.owned[reference]
	if !ok || objectID == "" {
		return "", fmt.Errorf("refusing cleanup: object %q is not owned by this test execution", reference)
	}
	return objectID, nil
}

func (s *ExecutionState) Values() map[string]string {
	result := make(map[string]string, len(s.values))
	for key, value := range s.values {
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
