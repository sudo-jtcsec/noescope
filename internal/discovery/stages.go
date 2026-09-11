package discovery

import "fmt"

type Stage string

const (
	StageArchitecture   Stage = "architecture"
	StageAuthentication Stage = "authentication"
	StageAuthorization  Stage = "authorization"
	StageEntities       Stage = "entities"
	StageSurface        Stage = "surface"
	StageFeatures       Stage = "features"
)

var orderedStages = []Stage{
	StageArchitecture,
	StageAuthentication,
	StageAuthorization,
	StageEntities,
	StageSurface,
	StageFeatures,
}

func ParseThrough(value string) (Stage, error) {
	if value == "" {
		return StageFeatures, nil
	}

	stage := Stage(value)
	for _, candidate := range orderedStages {
		if stage == candidate {
			return stage, nil
		}
	}

	return "", fmt.Errorf(
		"unknown discovery stage %q (supported: architecture, authentication, authorization, entities, surface, features)",
		value,
	)
}

func (s Stage) Count() int {
	for i, candidate := range orderedStages {
		if s == candidate {
			return i + 1
		}
	}
	return 0
}

func ValidateResumeTarget(recorded, requested Stage) error {
	if recorded.Count() == 0 || requested.Count() == 0 {
		return fmt.Errorf("invalid resume stage transition %q -> %q", recorded, requested)
	}
	if requested.Count() < recorded.Count() {
		return fmt.Errorf(
			"cannot move resumed run target backward from %s to %s",
			recorded,
			requested,
		)
	}
	return nil
}
