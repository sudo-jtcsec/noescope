package testsmodel

import "time"

const SchemaVersion = "0.1"

const (
	KindCore = "core"

	StatusCandidate     = "candidate"
	StatusBlocked       = "blocked"
	StatusNotAttempted  = "not_attempted"
	StatusPassed        = "passed"
	StatusFailed        = "failed"
	StatusCleanupFailed = "cleanup_failed"
	StatusUnresolved    = "unresolved"
)

type TestPack struct {
	SchemaVersion string     `json:"schema_version"`
	TestPackID    string     `json:"test_pack_id"`
	SourceRunID   string     `json:"source_run_id"`
	RuntimeRunID  string     `json:"runtime_run_id"`
	GitCommit     string     `json:"git_commit"`
	Identity      string     `json:"identity,omitempty"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Tests         []TestCase `json:"tests"`
}

type TestCase struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Kind            string           `json:"kind"`
	Description     string           `json:"description"`
	FeatureIDs      []string         `json:"feature_ids"`
	InterfaceIDs    []string         `json:"interface_ids"`
	EntityIDs       []string         `json:"entity_ids"`
	Preconditions   Preconditions    `json:"preconditions"`
	GeneratedValues []ValueReference `json:"generated_values"`
	Steps           []Step           `json:"steps"`
	Assertions      []Assertion      `json:"assertions"`
	Cleanup         []CleanupStep    `json:"cleanup"`
	Safety          SafetyMetadata   `json:"safety"`
	EvidenceIDs     []string         `json:"evidence_ids"`
}

type Preconditions struct {
	Authentication string `json:"authentication"`
}

type Step struct {
	Type        string          `json:"type"`
	InterfaceID string          `json:"interface_id,omitempty"`
	Field       string          `json:"field,omitempty"`
	Target      string          `json:"target,omitempty"`
	Value       *ValueReference `json:"value,omitempty"`
}

type ValueReference struct {
	Reference string `json:"reference,omitempty"`
	Generated string `json:"generated,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
}

type Assertion struct {
	Type        string `json:"type"`
	Match       string `json:"match,omitempty"`
	Expected    string `json:"expected,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	InterfaceID string `json:"interface_id,omitempty"`
}

type CleanupStep struct {
	Type           string `json:"type"`
	InterfaceID    string `json:"interface_id,omitempty"`
	OwnedReference string `json:"owned_reference,omitempty"`
}

type SafetyMetadata struct {
	Classification    string   `json:"classification"`
	Mutating          bool     `json:"mutating"`
	RequiresOwnedData bool     `json:"requires_owned_data"`
	CleanupRequired   bool     `json:"cleanup_required"`
	SelectionScore    int      `json:"selection_score"`
	SelectionReasons  []string `json:"selection_reasons"`
}

type Execution struct {
	SchemaVersion string            `json:"schema_version"`
	TestPackID    string            `json:"test_pack_id"`
	SourceRunID   string            `json:"source_run_id"`
	RuntimeRunID  string            `json:"runtime_run_id"`
	GitCommit     string            `json:"git_commit"`
	Identity      string            `json:"identity,omitempty"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	Results       []CandidateResult `json:"results"`
	Summary       ExecutionSummary  `json:"summary"`
}

type CandidateResult struct {
	Candidate   TestCase          `json:"candidate"`
	Status      string            `json:"status"`
	Reason      string            `json:"reason,omitempty"`
	EvidenceIDs []string          `json:"evidence_ids"`
	Values      map[string]string `json:"values,omitempty"`
}

type ExecutionSummary struct {
	Candidates    int `json:"candidates"`
	Passed        int `json:"passed"`
	Blocked       int `json:"blocked"`
	Failed        int `json:"failed"`
	CleanupFailed int `json:"cleanup_failed"`
	Unresolved    int `json:"unresolved"`
	NotAttempted  int `json:"not_attempted"`
}

type Baseline struct {
	SchemaVersion   string   `json:"schema_version"`
	SourceRunID     string   `json:"source_run_id"`
	RuntimeRunID    string   `json:"runtime_run_id"`
	GitCommit       string   `json:"git_commit"`
	TestPackID      string   `json:"test_pack_id"`
	VerifiedTestIDs []string `json:"verified_test_ids"`
}
