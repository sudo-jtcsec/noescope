package features

import (
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

type InterfaceMappingCounts struct {
	ConcreteActions int
	RootOnlyActions int
	UnmappedActions int
}

func (c InterfaceMappingCounts) Actions() int {
	return c.ConcreteActions + c.RootOnlyActions + c.UnmappedActions
}

type ConcreteInterfaceCoverageCounts struct {
	CandidateInterfaces    int
	ReferencedInterfaces   int
	UnreferencedInterfaces int
}

func IsRootInterface(item surface.Interface) bool {
	if strings.HasSuffix(item.ID, ".root") {
		return true
	}
	return item.Type == "api_endpoint" &&
		item.Locator.MethodName == "" &&
		item.Locator.Protocol != "" &&
		(item.Locator.TransportPath != "" || item.Locator.Path != "")
}

func CountInterfaceMappings(
	findings *Findings,
	surfaceFindings *surface.Findings,
) InterfaceMappingCounts {
	rootIDs := make(map[string]struct{})
	if surfaceFindings != nil {
		for _, item := range surfaceFindings.Interfaces {
			if IsRootInterface(item) {
				rootIDs[item.ID] = struct{}{}
			}
		}
	}
	var counts InterfaceMappingCounts
	if findings == nil {
		return counts
	}
	for _, node := range findings.Features {
		countNodeInterfaceMappings(node, rootIDs, &counts)
	}
	return counts
}

func countNodeInterfaceMappings(
	node Node,
	rootIDs map[string]struct{},
	counts *InterfaceMappingCounts,
) {
	if node.Type == "action" {
		if len(node.InterfaceIDs) == 0 {
			counts.UnmappedActions++
		} else {
			rootOnly := true
			for _, interfaceID := range node.InterfaceIDs {
				if _, root := rootIDs[interfaceID]; !root {
					rootOnly = false
					break
				}
			}
			if rootOnly {
				counts.RootOnlyActions++
			} else {
				counts.ConcreteActions++
			}
		}
	}
	for _, child := range node.Children {
		countNodeInterfaceMappings(child, rootIDs, counts)
	}
}

func CountConcreteInterfaceCoverage(
	findings *Findings,
	surfaceFindings *surface.Findings,
) ConcreteInterfaceCoverageCounts {
	candidates := stringSet(ConcreteCandidateInterfaceIDs(surfaceFindings))
	referenced := map[string]struct{}{}
	if findings != nil {
		for _, node := range findings.Features {
			collectReferencedCandidates(node, candidates, referenced)
		}
	}
	return ConcreteInterfaceCoverageCounts{
		CandidateInterfaces: len(candidates), ReferencedInterfaces: len(referenced),
		UnreferencedInterfaces: len(candidates) - len(referenced),
	}
}

func collectReferencedCandidates(
	node Node,
	candidates map[string]struct{},
	referenced map[string]struct{},
) {
	for _, id := range node.InterfaceIDs {
		if _, ok := candidates[id]; ok {
			referenced[id] = struct{}{}
		}
	}
	for _, child := range node.Children {
		collectReferencedCandidates(child, candidates, referenced)
	}
}

func ValidateCanonicalResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) error {
	return validateResultWithReferences(
		result,
		evidence,
		referencesFromFindings(
			authorizationFindings,
			entityFindings,
			surfaceFindings,
		),
	)
}
