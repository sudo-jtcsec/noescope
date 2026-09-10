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

func TestSubmitSchemaIsValidJSON(t *testing.T) {
	if !json.Valid(Task().SubmitSchema) {
		t.Fatal("authentication submission schema is not valid JSON")
	}
}

func TestValidateResultRejectsStringifiedFindings(t *testing.T) {
	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: json.RawMessage(`"{\"authentication_present\":false}"`),
	}

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"authentication findings: expected object, got string",
	) {
		t.Fatalf("expected useful stringified findings error, got %v", err)
	}
}

func TestValidateResultRejectsStringSession(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "authentication_present": true,
      "confidence": 0.9,
      "evidence_ids": ["ev_login"],
      "mechanisms": [{
        "id": "web-session",
        "type": "form_session",
        "login_entrypoints": [],
        "credential_fields": [],
        "session": "cookie",
        "established_by": [],
        "checked_by": [],
        "source_components": ["auth.go"],
        "confidence": 0.9,
        "evidence_ids": ["ev_login"]
      }]
    }`))

	err := validateResult(result, testEvidence{"ev_login": true})
	if err == nil || !strings.Contains(
		err.Error(),
		"mechanisms[0].session: expected object, got string",
	) {
		t.Fatalf("expected useful session error, got %v", err)
	}
}

func TestValidateResultRejectsStringMechanisms(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "authentication_present": false,
      "confidence": 0.9,
      "evidence_ids": ["ev_search"],
      "mechanisms": "none"
    }`))

	err := validateResult(result, testEvidence{"ev_search": true})
	if err == nil || !strings.Contains(
		err.Error(),
		"mechanisms: expected array, got string",
	) {
		t.Fatalf("expected useful mechanisms error, got %v", err)
	}
}

func TestValidateResultRejectsStringLogout(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "authentication_present": true,
      "confidence": 0.9,
      "evidence_ids": ["ev_login"],
      "mechanisms": [{
        "id": "web-session",
        "type": "form_session",
        "login_entrypoints": [],
        "credential_fields": [],
        "established_by": [],
        "checked_by": [],
        "logout": "/logout",
        "source_components": ["auth.go"],
        "confidence": 0.9,
        "evidence_ids": ["ev_login"]
      }]
    }`))

	err := validateResult(result, testEvidence{"ev_login": true})
	if err == nil || !strings.Contains(
		err.Error(),
		"mechanisms[0].logout: expected object, got string",
	) {
		t.Fatalf("expected useful logout error, got %v", err)
	}
}

func TestValidateResultRejectsStringSourceComponents(t *testing.T) {
	result := resultWithRawFindings(json.RawMessage(`{
      "authentication_present": true,
      "confidence": 0.9,
      "evidence_ids": ["ev_login"],
      "mechanisms": [{
        "id": "web-session",
        "type": "form_session",
        "login_entrypoints": [],
        "credential_fields": [],
        "established_by": [],
        "checked_by": [],
        "source_components": "auth.go",
        "confidence": 0.9,
        "evidence_ids": ["ev_login"]
      }]
    }`))

	err := validateResult(result, testEvidence{"ev_login": true})
	if err == nil || !strings.Contains(
		err.Error(),
		"mechanisms[0].source_components: expected array, got string",
	) {
		t.Fatalf("expected useful source_components error, got %v", err)
	}
}

func TestValidateResultAcceptsSupportedAuthentication(t *testing.T) {
	result := resultWithFindings(t, Findings{
		AuthenticationPresent: true,
		Confidence:            0.9,
		EvidenceIDs:           []string{"ev_login"},
		Mechanisms: []Mechanism{
			validMechanism(
				"web-session",
				"form_session",
				0.9,
				[]string{"ev_login"},
			),
		},
	})

	if err := validateResult(
		result,
		testEvidence{"ev_login": true},
	); err != nil {
		t.Fatalf("expected valid result, got %v", err)
	}
}

func TestNormalizedAuthenticationFindingsStillValidate(t *testing.T) {
	findings := Findings{
		AuthenticationPresent: false,
		Confidence:            0.98,
		EvidenceIDs:           []string{"ev_auth_search"},
		Mechanisms:            []Mechanism{},
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	doubleEncoded, err := json.Marshal(string(data))
	if err != nil {
		t.Fatal(err)
	}

	normalized, changed, err := investigation.NormalizeFindings(doubleEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected authentication findings normalization")
	}

	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: normalized,
	}
	if err := validateResult(
		result,
		testEvidence{"ev_auth_search": true},
	); err != nil {
		t.Fatalf("normalized authentication findings did not validate: %v", err)
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
			validMechanism("api-token", "bearer", 0.8, []string{}),
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
			validMechanism(
				"api-token",
				"bearer",
				0.8,
				[]string{"ev_unknown"},
			),
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
			validMechanism(
				"api-token",
				"bearer",
				1.1,
				[]string{"ev_token"},
			),
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

func validMechanism(
	id string,
	mechanismType string,
	confidence float64,
	evidenceIDs []string,
) Mechanism {
	return Mechanism{
		ID:               id,
		Type:             mechanismType,
		LoginEntrypoints: []string{},
		CredentialFields: []string{},
		EstablishedBy:    []string{},
		CheckedBy:        []string{},
		SourceComponents: []string{"auth.go"},
		Confidence:       confidence,
		EvidenceIDs:      evidenceIDs,
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

func resultWithRawFindings(findings json.RawMessage) *investigation.Result {
	return &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: findings,
	}
}
