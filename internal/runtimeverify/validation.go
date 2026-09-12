package runtimeverify

import (
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

type RuntimeEvidenceLookup interface {
	Exists(string) bool
}

var validStatuses = map[Status]struct{}{
	StatusVerified: {}, StatusPartiallyVerified: {}, StatusUnverified: {},
	StatusNotFound: {}, StatusAuthRequired: {}, StatusRedirected: {},
	StatusRuntimeError: {}, StatusNotAttempted: {}, StatusUnsafe: {},
	StatusUnknown: {}, StatusContradicted: {}, StatusRequiresRuntimeBinding: {},
	StatusBlocked: {},
}

var validRunStatuses = map[RunStatus]struct{}{
	RunStatusRunning: {}, RunStatusCompleted: {}, RunStatusPartial: {}, RunStatusFailed: {},
}

func ValidateRuntime(
	application *model.Application,
	runtime *Runtime,
	evidence RuntimeEvidenceLookup,
) error {
	if runtime.SchemaVersion != SchemaVersion {
		return fmt.Errorf("runtime schema version %q is incompatible", runtime.SchemaVersion)
	}
	if _, ok := validRunStatuses[runtime.Status]; !ok {
		return fmt.Errorf("runtime has invalid overall status %q", runtime.Status)
	}
	if runtime.SourceRunID != application.Metadata.RunID ||
		runtime.SourceGitCommit != application.Metadata.Source.GitCommit ||
		runtime.ApplicationSchemaVersion != application.SchemaVersion {
		return fmt.Errorf("runtime metadata does not match canonical source application")
	}
	interfaceIDs := map[string]struct{}{}
	for _, item := range application.Surface.Interfaces {
		interfaceIDs[item.ID] = struct{}{}
	}
	featureIDs := map[string]struct{}{}
	var collect func(features.Node)
	collect = func(node features.Node) {
		featureIDs[node.ID] = struct{}{}
		for _, child := range node.Children {
			collect(child)
		}
	}
	for _, node := range application.Features {
		collect(node)
	}
	if err := validateStatus("application", runtime.Application.Status); err != nil {
		return err
	}
	if err := validateStatus("authentication", runtime.Authentication.Status); err != nil {
		return err
	}
	if runtime.Authentication.PrimaryAuthentication != "" {
		if err := validateStatus("authentication.primary_authentication", runtime.Authentication.PrimaryAuthentication); err != nil {
			return err
		}
	}
	if second := runtime.Authentication.SecondFactor; second != nil {
		if second.Type != "totp" {
			return fmt.Errorf("authentication second factor has unsupported type %q", second.Type)
		}
		validSecondFactor := map[string]struct{}{
			"not_required": {}, "required": {}, "verified": {}, "failed": {}, "blocked": {}, "unknown": {},
		}
		if _, ok := validSecondFactor[second.Status]; !ok {
			return fmt.Errorf("authentication second factor has invalid status %q", second.Status)
		}
	}
	if err := validateEvidence(runtime.Application.EvidenceIDs, evidence); err != nil {
		return fmt.Errorf("application observation: %w", err)
	}
	if err := validateEvidence(runtime.Authentication.EvidenceIDs, evidence); err != nil {
		return fmt.Errorf("authentication observation: %w", err)
	}
	observationKeys := make(map[string]int, len(runtime.Interfaces))
	for index, item := range runtime.Interfaces {
		if _, ok := interfaceIDs[item.InterfaceID]; !ok {
			return fmt.Errorf("runtime interfaces[%d] references unknown canonical interface %q", index, item.InterfaceID)
		}
		if err := validateStatus(fmt.Sprintf("interfaces[%d]", index), item.Status); err != nil {
			return err
		}
		if item.State != "unauthenticated" && item.State != "authenticated" &&
			item.State != "not_attempted" {
			return fmt.Errorf("interfaces[%d] has invalid browser state %q", index, item.State)
		}
		key := item.InterfaceID + "\x00" + item.State
		if previous, exists := observationKeys[key]; exists {
			return fmt.Errorf(
				"runtime interfaces[%d] duplicates interface_id %q and state %q from interfaces[%d]",
				index, item.InterfaceID, item.State, previous,
			)
		}
		observationKeys[key] = index
		if err := validateEvidence(item.EvidenceIDs, evidence); err != nil {
			return fmt.Errorf("interfaces[%d]: %w", index, err)
		}
	}
	for index, item := range runtime.Features {
		if _, ok := featureIDs[item.FeatureID]; !ok {
			return fmt.Errorf("runtime features[%d] references unknown canonical feature %q", index, item.FeatureID)
		}
		if err := validateStatus(fmt.Sprintf("features[%d]", index), item.Status); err != nil {
			return err
		}
		for _, interfaceID := range append(append([]string{}, item.InterfaceIDs...), item.VerifiedInterfaceIDs...) {
			if _, ok := interfaceIDs[interfaceID]; !ok {
				return fmt.Errorf("runtime feature %q references unknown canonical interface %q", item.FeatureID, interfaceID)
			}
		}
	}
	for index, item := range runtime.ConsoleErrors {
		if item.InterfaceID != "" {
			if _, ok := interfaceIDs[item.InterfaceID]; !ok {
				return fmt.Errorf("runtime console_errors[%d] references unknown canonical interface %q", index, item.InterfaceID)
			}
		}
		if err := validateEvidence([]string{item.EvidenceID}, evidence); err != nil {
			return fmt.Errorf("console_errors[%d]: %w", index, err)
		}
	}
	for index, item := range runtime.ObservationErrors {
		if item.InterfaceID != "" {
			if _, ok := interfaceIDs[item.InterfaceID]; !ok {
				return fmt.Errorf("runtime observation_errors[%d] references unknown canonical interface %q", index, item.InterfaceID)
			}
		}
		if err := validateEvidence([]string{item.EvidenceID}, evidence); err != nil {
			return fmt.Errorf("observation_errors[%d]: %w", index, err)
		}
	}
	if runtime.Failure != nil && len(runtime.Failure.EvidenceIDs) > 0 {
		if err := validateEvidence(runtime.Failure.EvidenceIDs, evidence); err != nil {
			return fmt.Errorf("runtime failure: %w", err)
		}
	}
	return nil
}

func validateStatus(path string, status Status) error {
	if _, ok := validStatuses[status]; !ok {
		return fmt.Errorf("%s has invalid runtime status %q", path, status)
	}
	return nil
}

func validateEvidence(ids []string, evidence RuntimeEvidenceLookup) error {
	if len(ids) == 0 {
		return fmt.Errorf("has no runtime evidence")
	}
	for _, id := range ids {
		if id == "" || evidence == nil || !evidence.Exists(id) {
			return fmt.Errorf("references unknown runtime evidence ID %q", id)
		}
	}
	return nil
}
