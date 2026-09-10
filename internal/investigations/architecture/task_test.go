package architecture

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
		t.Fatal("architecture submission schema is not valid JSON")
	}
}

func TestValidateResultRejectsFrameworkWithoutDirectEvidence(t *testing.T) {
	findings := customMVCFindings()
	findings.Frameworks = []Technology{
		{
			Name:         "Slim",
			EvidenceType: "inferred",
			Confidence:   0.9,
			EvidenceIDs:  []string{"ev_structure"},
		},
	}

	err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{
			"ev_manifest":  true,
			"ev_structure": true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "requires direct framework evidence") {
		t.Fatalf("expected inferred framework rejection, got %v", err)
	}
}

func TestValidateResultAcceptsDirectFrameworkEvidence(t *testing.T) {
	findings := customMVCFindings()
	findings.Frameworks = []Technology{
		{
			Name:         "Laravel",
			EvidenceType: "direct",
			Confidence:   0.95,
			EvidenceIDs:  []string{"ev_framework_manifest"},
		},
	}

	err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{
			"ev_manifest":           true,
			"ev_framework_manifest": true,
		},
	)
	if err != nil {
		t.Fatalf("expected directly evidenced framework to be valid, got %v", err)
	}
}

func TestNormalizedArchitectureFindingsStillValidate(t *testing.T) {
	findings := customMVCFindings()
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
		t.Fatal("expected architecture findings normalization")
	}

	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: normalized,
	}
	if err := validateResult(
		result,
		testEvidence{"ev_manifest": true},
	); err != nil {
		t.Fatalf("normalized architecture findings did not validate: %v", err)
	}
}

func TestValidateResultAcceptsCustomMVCWithoutFramework(t *testing.T) {
	findings := customMVCFindings()

	if err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{"ev_manifest": true},
	); err != nil {
		t.Fatalf("expected custom MVC architecture to be valid, got %v", err)
	}
}

func TestKanboardLikeManifestDoesNotImplySlim(t *testing.T) {
	manifest := json.RawMessage(`{
      "require": {
        "php": ">=8.1.0",
        "pimple/pimple": "3.6.2",
        "symfony/console": "5.4.41"
      }
    }`)
	var dependencies struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(manifest, &dependencies); err != nil {
		t.Fatal(err)
	}
	if _, exists := dependencies.Require["slim/slim"]; exists {
		t.Fatal("fixture unexpectedly contains Slim")
	}

	findings := customMVCFindings()
	findings.Libraries = []Technology{
		{
			Name:         "Pimple",
			Role:         "dependency injection container",
			EvidenceType: "direct",
			Confidence:   0.95,
			EvidenceIDs:  []string{"ev_manifest"},
		},
		{
			Name:         "Symfony Console",
			Role:         "console tooling",
			EvidenceType: "direct",
			Confidence:   0.95,
			EvidenceIDs:  []string{"ev_manifest"},
		},
	}

	if err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{"ev_manifest": true},
	); err != nil {
		t.Fatalf("expected Kanboard-like manifest model to be valid, got %v", err)
	}

	findings.Frameworks = []Technology{
		{
			Name:         "Slim",
			EvidenceType: "inferred",
			Confidence:   0.9,
			EvidenceIDs:  []string{"ev_manifest"},
		},
	}
	if err := validateResult(
		resultWithFindings(t, findings),
		testEvidence{"ev_manifest": true},
	); err == nil || !strings.Contains(err.Error(), "requires direct framework evidence") {
		t.Fatalf("expected fixture-derived Slim inference to be rejected, got %v", err)
	}
}

func TestValidateResultRejectsStringifiedArchitectureFindings(t *testing.T) {
	result := &investigation.Result{
		Status:   "completed",
		Summary:  "test result",
		Findings: json.RawMessage(`"{\"frameworks\":[]}"`),
	}

	err := validateResult(result, testEvidence{})
	if err == nil || !strings.Contains(
		err.Error(),
		"architecture findings: expected object, got string",
	) {
		t.Fatalf("expected useful stringified findings error, got %v", err)
	}
}

func TestTaskRequiresDirectFrameworkEvidenceAndAvoidsStructuralInference(
	t *testing.T,
) {
	prompt := Task().Objective + "\n" + Task().Instructions
	for _, expected := range []string{
		"Check dependency manifests before naming frameworks",
		"Never identify a named framework from Controller/Model/Template directories",
		"Do not infer PSR-7 or PSR-15",
		"Framework absence is a valid result",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("architecture prompt does not contain %q", expected)
		}
	}

	if !strings.Contains(
		string(Task().SubmitSchema),
		`"enum": ["direct"]`,
	) {
		t.Fatal("framework schema does not require direct evidence type")
	}
}

func customMVCFindings() Findings {
	return Findings{
		Languages:          []Technology{},
		Formats:            []Technology{},
		Frameworks:         []Technology{},
		Libraries:          []Technology{},
		Databases:          []Technology{},
		WebServers:         []Technology{},
		ExternalInterfaces: []Technology{},
		ArchitectureStyle: Statement{
			Value:       "custom PHP MVC-style application",
			Confidence:  0.9,
			EvidenceIDs: []string{"ev_manifest"},
		},
		Entrypoints:          []Entrypoint{},
		ImportantDirectories: []Directory{},
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
