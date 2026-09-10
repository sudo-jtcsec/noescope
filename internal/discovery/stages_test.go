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
		{"", StageSurface, 5},
		{"architecture", StageArchitecture, 1},
		{"authentication", StageAuthentication, 2},
		{"authorization", StageAuthorization, 3},
		{"entities", StageEntities, 4},
		{"surface", StageSurface, 5},
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
	_, err := ParseThrough("features")
	if err == nil || !strings.Contains(err.Error(), "unknown discovery stage") {
		t.Fatalf("unexpected error: %v", err)
	}
}
