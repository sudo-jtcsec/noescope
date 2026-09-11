package discovery

import (
	"strings"
	"testing"
)

func TestParseThroughStageCounts(t *testing.T) {
	tests := []struct {
		value string
		stage Stage
		count int
	}{
		{"", StageFeatures, 6},
		{"architecture", StageArchitecture, 1},
		{"authentication", StageAuthentication, 2},
		{"authorization", StageAuthorization, 3},
		{"entities", StageEntities, 4},
		{"surface", StageSurface, 5},
		{"features", StageFeatures, 6},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			stage, err := ParseThrough(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if stage != test.stage || stage.Count() != test.count {
				t.Fatalf("got stage=%q count=%d", stage, stage.Count())
			}
		})
	}
}

func TestParseThroughRejectsUnknownStage(t *testing.T) {
	_, err := ParseThrough("workflows")
	if err == nil || !strings.Contains(err.Error(), "unknown discovery stage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateResumeTargetAllowsForwardExtensionAndRejectsBackward(t *testing.T) {
	if err := ValidateResumeTarget(StageSurface, StageFeatures); err != nil {
		t.Fatalf("forward resume extension rejected: %v", err)
	}
	if err := ValidateResumeTarget(StageFeatures, StageFeatures); err != nil {
		t.Fatalf("unchanged resume target rejected: %v", err)
	}
	if err := ValidateResumeTarget(StageFeatures, StageAuthentication); err == nil ||
		!strings.Contains(err.Error(), "backward") {
		t.Fatalf("expected backward target rejection, got %v", err)
	}
}
