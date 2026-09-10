package authentication

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
)

type testEvidence map[string]bool

func (e testEvidence) Exists(id string) bool {
	return e[id]
}

func TestValidateResultAcceptsSupportedAuthentication(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_login"},
		Mechanisms: []Mechanism{
			{
				ID:          "web-session",
				Type:        "form_session",
				Confidence:  0.9,
				EvidenceIDs: []string{"ev_login"},
			},
		},
	})

	if err := validateResult(
		result,
		testEvidence{"ev_login": true},
	); err != nil {
		t.Fatalf("expected valid result, got %v", err)
	}
}

func TestValidateResultAcceptsNoAuthentication(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: false,
		Confidence:            0.98,
		EvidenceIDs:           []string{"ev_auth_search"},
		Mechanisms:            []Mechanism{},
	})

	if err := validateResult(
		result,
		testEvidence{"ev_auth_search": true},
	); err != nil {
		t.Fatalf("expected no-authentication result to be valid, got %v", err)
	}
}

func TestValidateResultRejectsNoAuthenticationWithoutEvidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: false,
		Confidence:            0.98,
		EvidenceIDs:           []string{},
		Mechanisms:            []Mechanism{},
	})

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing conclusion evidence error, got %v", err)
	}
}

func TestValidateResultRejectsUnknownConclusionEvidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: false,
		Confidence:            0.98,
		EvidenceIDs:           []string{"ev_unknown"},
		Mechanisms:            []Mechanism{},
	})

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("expected unknown conclusion evidence error, got %v", err)
	}
}

func TestValidateResultRejectsInvalidConclusionConfidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: false,
		Confidence:            1.1,
		EvidenceIDs:           []string{"ev_auth_search"},
		Mechanisms:            []Mechanism{},
	})

	err := validateResult(
		result,
		testEvidence{"ev_auth_search": true},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid confidence") {
		t.Fatalf("expected conclusion confidence error, got %v", err)
	}
}

func TestValidateResultRejectsPositiveConfidenceWithoutEvidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_presence"},
		Mechanisms: []Mechanism{
			{
				ID:         "api-token",
				Type:       "bearer",
				Confidence: 0.8,
			},
		},
	})

	err := validateResult(
		result,
		testEvidence{"ev_presence": true},
	)
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("expected missing-evidence error, got %v", err)
	}
}

func TestValidateResultRejectsUnknownEvidenceID(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_presence"},
		Mechanisms: []Mechanism{
			{
				ID:          "api-token",
				Type:        "bearer",
				Confidence:  0.8,
				EvidenceIDs: []string{"ev_unknown"},
			},
		},
	})

	err := validateResult(
		result,
		testEvidence{"ev_presence": true},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("expected unknown-evidence error, got %v", err)
	}
}

func TestValidateResultRejectsInvalidConfidence(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_presence"},
		Mechanisms: []Mechanism{
			{
				ID:          "api-token",
				Type:        "bearer",
				Confidence:  1.1,
				EvidenceIDs: []string{"ev_token"},
			},
		},
	})

	err := validateResult(
		result,
		testEvidence{
			"ev_presence": true,
			"ev_token":    true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid confidence") {
		t.Fatalf("expected confidence error, got %v", err)
	}
}

func resultWithFindings(
	t *testing.T,
	findings Findings,
) *investigation.Result {
	t.Helper()

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}

	return &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: data,
	}
}
