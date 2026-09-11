package runtimeverify

import (
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

func TestFeatureCoverageUsesOnlyCanonicalInterfaceReferences(t *testing.T) {
	application := &model.Application{
		Surface: surface.Findings{Interfaces: []surface.Interface{{ID: "web.tasks"}, {ID: "api.task.get"}}},
		Features: []features.Node{{
			ID: "tasks", Type: "module", Children: []features.Node{{
				ID: "tasks.view", Type: "action", InterfaceIDs: []string{"web.tasks", "api.task.get"},
			}},
		}},
	}
	coverage := FeatureCoverage(application, []InterfaceObservation{
		{InterfaceID: "web.tasks", Status: StatusVerified},
		{InterfaceID: "unrelated", Status: StatusVerified},
		{InterfaceID: "api.task.get", Status: StatusNotAttempted},
	})
	byID := map[string]FeatureObservation{}
	for _, item := range coverage {
		byID[item.FeatureID] = item
	}
	action := byID["tasks.view"]
	if action.Status != StatusPartiallyVerified || len(action.VerifiedInterfaceIDs) != 1 ||
		action.VerifiedInterfaceIDs[0] != "web.tasks" {
		t.Fatalf("unexpected action coverage: %#v", action)
	}
	module := byID["tasks"]
	if module.Status != StatusPartiallyVerified || len(module.InterfaceIDs) != 2 {
		t.Fatalf("module did not aggregate descendant interfaces: %#v", module)
	}
}

func TestValidateSourceReferencesRejectsUnknownInterface(t *testing.T) {
	application := &model.Application{Features: []features.Node{{
		ID: "tasks", InterfaceIDs: []string{"invented.interface"},
	}}}
	err := ValidateSourceReferences(application)
	if err == nil || !strings.Contains(err.Error(), "unknown interface") {
		t.Fatalf("expected unknown interface rejection, got %v", err)
	}
}

func TestValidateRuntimeRejectsUnknownCanonicalInterfaceReference(t *testing.T) {
	application := runtimeApplicationFixture()
	runtime := &Runtime{
		SchemaVersion: SchemaVersion, SourceRunID: application.Metadata.RunID,
		Status:                   RunStatusCompleted,
		SourceGitCommit:          application.Metadata.Source.GitCommit,
		ApplicationSchemaVersion: application.SchemaVersion,
		Application:              ApplicationObservation{Status: StatusVerified, EvidenceIDs: []string{"ev"}},
		Authentication:           AuthenticationObservation{Status: StatusNotAttempted, EvidenceIDs: []string{"ev"}},
		Interfaces:               []InterfaceObservation{{InterfaceID: "invented.interface", Status: StatusVerified, EvidenceIDs: []string{"ev"}}},
	}
	err := ValidateRuntime(application, runtime, testRuntimeEvidence{"ev": true})
	if err == nil || !strings.Contains(err.Error(), "unknown canonical interface") {
		t.Fatalf("expected runtime interface rejection, got %v", err)
	}
}

type testRuntimeEvidence map[string]bool

func (e testRuntimeEvidence) Exists(id string) bool { return e[id] }

func TestFeatureCoverageIsDeterministic(t *testing.T) {
	application := &model.Application{
		Surface:  surface.Findings{Interfaces: []surface.Interface{{ID: "b"}, {ID: "a"}}},
		Features: []features.Node{{ID: "module", InterfaceIDs: []string{"b", "a"}}},
	}
	first := FeatureCoverage(application, []InterfaceObservation{{InterfaceID: "a", Status: StatusVerified}})
	second := FeatureCoverage(application, []InterfaceObservation{{InterfaceID: "a", Status: StatusVerified}})
	if len(first) != 1 || first[0].InterfaceIDs[0] != "a" || first[0].InterfaceIDs[1] != "b" ||
		first[0].Status != second[0].Status {
		t.Fatalf("coverage is not deterministic: %#v / %#v", first, second)
	}
}

func TestFeatureCoveragePrefersAuthenticatedVerificationOverExpectedAuthWall(t *testing.T) {
	application := &model.Application{
		Surface: surface.Findings{Interfaces: []surface.Interface{{
			ID: "web.dashboard", Access: &surface.Access{Authentication: "required"},
		}}},
		Features: []features.Node{{
			ID: "dashboard.view", Type: "action", InterfaceIDs: []string{"web.dashboard"},
		}},
	}
	coverage := FeatureCoverage(application, []InterfaceObservation{
		{InterfaceID: "web.dashboard", State: "unauthenticated", Status: StatusAuthRequired},
		{InterfaceID: "web.dashboard", State: "authenticated", Status: StatusVerified},
	})
	if len(coverage) != 1 || coverage[0].Status != StatusVerified {
		t.Fatalf("expected auth wall to preserve authenticated verification: %#v", coverage)
	}
}

func TestFeatureCoverageAcceptsPublicUnauthenticatedVerification(t *testing.T) {
	application := &model.Application{
		Surface: surface.Findings{Interfaces: []surface.Interface{{
			ID: "web.login", Access: &surface.Access{Authentication: "not_required"},
		}}},
		Features: []features.Node{{
			ID: "session.login", Type: "action", InterfaceIDs: []string{"web.login"},
		}},
	}
	coverage := FeatureCoverage(application, []InterfaceObservation{{
		InterfaceID: "web.login", State: "unauthenticated", Status: StatusVerified,
	}})
	if len(coverage) != 1 || coverage[0].Status != StatusVerified {
		t.Fatalf("public unauthenticated verification was not sufficient: %#v", coverage)
	}
}

func TestValidateRuntimeScopesInterfaceUniquenessByState(t *testing.T) {
	application := runtimeApplicationFixture()
	runtime := &Runtime{
		SchemaVersion: SchemaVersion, SourceRunID: application.Metadata.RunID,
		Status:                   RunStatusCompleted,
		SourceGitCommit:          application.Metadata.Source.GitCommit,
		ApplicationSchemaVersion: application.SchemaVersion,
		Application:              ApplicationObservation{Status: StatusVerified, EvidenceIDs: []string{"ev"}},
		Authentication:           AuthenticationObservation{Status: StatusVerified, EvidenceIDs: []string{"ev"}},
		Interfaces: []InterfaceObservation{
			{InterfaceID: "web.admin", State: "unauthenticated", Status: StatusAuthRequired, EvidenceIDs: []string{"ev"}},
			{InterfaceID: "web.admin", State: "authenticated", Status: StatusVerified, EvidenceIDs: []string{"ev"}},
		},
	}
	if err := ValidateRuntime(application, runtime, testRuntimeEvidence{"ev": true}); err != nil {
		t.Fatalf("same interface in distinct states was rejected: %v", err)
	}
	runtime.Interfaces = append(runtime.Interfaces, InterfaceObservation{
		InterfaceID: "web.admin", State: "authenticated", Status: StatusVerified,
		EvidenceIDs: []string{"ev"},
	})
	err := ValidateRuntime(application, runtime, testRuntimeEvidence{"ev": true})
	if err == nil || !strings.Contains(err.Error(), "duplicates interface_id") {
		t.Fatalf("duplicate interface/state observation was not rejected: %v", err)
	}
}
