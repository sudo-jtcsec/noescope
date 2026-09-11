package runtimeverify

import (
	"fmt"
	"sort"

	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/model"
)

func ValidateSourceReferences(application *model.Application) error {
	interfaces := map[string]struct{}{}
	for _, item := range application.Surface.Interfaces {
		if _, exists := interfaces[item.ID]; exists {
			return fmt.Errorf("source application contains duplicate interface ID %q", item.ID)
		}
		interfaces[item.ID] = struct{}{}
	}
	seenFeatures := map[string]struct{}{}
	var validateNode func(features.Node) error
	validateNode = func(node features.Node) error {
		if _, exists := seenFeatures[node.ID]; exists {
			return fmt.Errorf("source application contains duplicate feature ID %q", node.ID)
		}
		seenFeatures[node.ID] = struct{}{}
		for _, interfaceID := range node.InterfaceIDs {
			if _, ok := interfaces[interfaceID]; !ok {
				return fmt.Errorf("feature %q references unknown interface %q", node.ID, interfaceID)
			}
		}
		for _, child := range node.Children {
			if err := validateNode(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, node := range application.Features {
		if err := validateNode(node); err != nil {
			return err
		}
	}
	return nil
}

func FeatureCoverage(
	application *model.Application,
	observations []InterfaceObservation,
) []FeatureObservation {
	byInterface := map[string][]Status{}
	for _, observation := range observations {
		byInterface[observation.InterfaceID] = append(
			byInterface[observation.InterfaceID], observation.Status,
		)
	}
	result := make([]FeatureObservation, 0)
	var walk func(features.Node) []string
	walk = func(node features.Node) []string {
		ids := append([]string(nil), node.InterfaceIDs...)
		hasDirectInterfaces := len(ids) > 0
		for _, child := range node.Children {
			childIDs := walk(child)
			if !hasDirectInterfaces && node.Type != "action" {
				ids = append(ids, childIDs...)
			}
		}
		ids = sortedUniqueStrings(ids)
		verified := make([]string, 0)
		attempted := false
		contradicted := false
		for _, interfaceID := range ids {
			for _, status := range byInterface[interfaceID] {
				switch status {
				case StatusVerified:
					verified = appendUniqueSorted(verified, interfaceID)
					attempted = true
				case StatusNotFound, StatusRuntimeError, StatusContradicted:
					attempted = true
					contradicted = true
				case StatusAuthRequired, StatusRedirected:
					attempted = true
				}
			}
		}
		status := StatusNotAttempted
		switch {
		case len(ids) > 0 && len(verified) == len(ids):
			status = StatusVerified
		case len(verified) > 0:
			status = StatusPartiallyVerified
		case contradicted:
			status = StatusContradicted
		case attempted:
			status = StatusUnverified
		}
		result = append(result, FeatureObservation{
			FeatureID: node.ID, Status: status, InterfaceIDs: ids,
			VerifiedInterfaceIDs: verified,
		})
		return ids
	}
	for _, node := range application.Features {
		walk(node)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FeatureID < result[j].FeatureID })
	return result
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	if len(values) < 2 {
		return values
	}
	write := 1
	for _, value := range values[1:] {
		if value != values[write-1] {
			values[write] = value
			write++
		}
	}
	return values[:write]
}
