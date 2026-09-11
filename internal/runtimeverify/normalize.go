package runtimeverify

import "sort"

func normalizeRuntime(value *Runtime) {
	value.StartedAt = value.StartedAt.UTC()
	value.CompletedAt = value.CompletedAt.UTC()
	value.Application.EvidenceIDs = sortedUniqueStrings(value.Application.EvidenceIDs)
	value.Authentication.EvidenceIDs = sortedUniqueStrings(value.Authentication.EvidenceIDs)
	if value.Failure != nil {
		value.Failure.EvidenceIDs = sortedUniqueStrings(value.Failure.EvidenceIDs)
	}
	for index := range value.Interfaces {
		value.Interfaces[index].EvidenceIDs = sortedUniqueStrings(value.Interfaces[index].EvidenceIDs)
	}
	sort.Slice(value.Interfaces, func(i, j int) bool {
		left := value.Interfaces[i].InterfaceID + "\x00" + value.Interfaces[i].State + "\x00" + string(value.Interfaces[i].Status)
		right := value.Interfaces[j].InterfaceID + "\x00" + value.Interfaces[j].State + "\x00" + string(value.Interfaces[j].Status)
		return left < right
	})
	for index := range value.Features {
		value.Features[index].InterfaceIDs = sortedUniqueStrings(value.Features[index].InterfaceIDs)
		value.Features[index].VerifiedInterfaceIDs = sortedUniqueStrings(value.Features[index].VerifiedInterfaceIDs)
	}
	sort.Slice(value.Features, func(i, j int) bool {
		return value.Features[i].FeatureID < value.Features[j].FeatureID
	})
	sort.Slice(value.ConsoleErrors, func(i, j int) bool {
		left := value.ConsoleErrors[i].InterfaceID + "\x00" + value.ConsoleErrors[i].State + "\x00" + value.ConsoleErrors[i].Message
		right := value.ConsoleErrors[j].InterfaceID + "\x00" + value.ConsoleErrors[j].State + "\x00" + value.ConsoleErrors[j].Message
		return left < right
	})
	sort.Slice(value.ObservationErrors, func(i, j int) bool {
		left := value.ObservationErrors[i].Phase + "\x00" + value.ObservationErrors[i].Operation + "\x00" + value.ObservationErrors[i].InterfaceID + "\x00" + value.ObservationErrors[i].State
		right := value.ObservationErrors[j].Phase + "\x00" + value.ObservationErrors[j].Operation + "\x00" + value.ObservationErrors[j].InterfaceID + "\x00" + value.ObservationErrors[j].State
		return left < right
	})
}
