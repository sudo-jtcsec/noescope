package discovery

import "fmt"

type Stage string

const (
	StageArchitecture   Stage = "architecture"
	StageAuthentication Stage = "authentication"
	StageAuthorization  Stage = "authorization"
	StageEntities       Stage = "entities"
	StageSurface        Stage = "surface"
)

var orderedStages = []Stage{
	StageArchitecture,
	StageAuthentication,
	StageAuthorization,
	StageEntities,
	StageSurface,
}

func ParseThrough(value string) (Stage, error) {
	if value == "" {
		return StageSurface, nil
	}

	stage := Stage(value)
	for _, candidate := range orderedStages {
		if stage == candidate {
			return stage, nil
		}
	}

	return "", fmt.Errorf(
		"unknown discovery stage %q (supported: architecture, authentication, authorization, entities, surface)",
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
