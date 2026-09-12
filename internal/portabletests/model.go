package portabletests

import "time"

const (
	SchemaVersion = "0.1"
	RunnerVersion = "0.1"
)

const (
	StatusPassed        = "passed"
	StatusFailed        = "failed"
	StatusBlocked       = "blocked"
	StatusCleanupFailed = "cleanup_failed"
	StatusUnresolved    = "unresolved"
	StatusNotRun        = "not_run"
)

type Manifest struct {
	SchemaVersion  string              `json:"schema_version"`
	RunnerVersion  string              `json:"runner_version"`
	PackID         string              `json:"pack_id"`
	Project        string              `json:"project"`
	SourceRunID    string              `json:"source_run_id"`
	RuntimeRunID   string              `json:"runtime_run_id"`
	SourceCommit   string              `json:"source_commit"`
	CreatedAt      time.Time           `json:"created_at"`
	DefaultTarget  string              `json:"default_target"`
	TestIDs        []string            `json:"test_ids"`
	TestCount      int                 `json:"test_count"`
	Identities     []IdentityReference `json:"identities"`
	Authentication Authentication      `json:"authentication"`
	Provenance     Provenance          `json:"provenance"`
}

type IdentityReference struct {
	ID          string         `json:"id"`
	UsernameEnv string         `json:"username_env"`
	PasswordEnv string         `json:"password_env"`
	TOTP        *TOTPReference `json:"totp,omitempty"`
}

type TOTPReference struct {
	SecretEnv string `json:"secret_env"`
	Period    uint   `json:"period,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

type Authentication struct {
	LoginPath string `json:"login_path"`
}

type Provenance struct {
	Generator        string `json:"generator"`
	SourceTestPackID string `json:"source_test_pack_id"`
	SourceRunID      string `json:"source_run_id"`
	RuntimeRunID     string `json:"runtime_run_id"`
}

type IntegrityLock struct {
	SchemaVersion string            `json:"schema_version"`
	RunnerVersion string            `json:"runner_version"`
	Files         map[string]string `json:"files"`
}

type Test struct {
	SchemaVersion   string           `json:"schema_version"`
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Kind            string           `json:"kind"`
	Description     string           `json:"description"`
	Identity        string           `json:"identity,omitempty"`
	FeatureIDs      []string         `json:"feature_ids"`
	InterfaceIDs    []string         `json:"interface_ids"`
	EntityIDs       []string         `json:"entity_ids"`
	Interfaces      []Interface      `json:"interfaces"`
	Preconditions   Preconditions    `json:"preconditions"`
	GeneratedValues []ValueReference `json:"generated_values"`
	Steps           []Step           `json:"steps"`
	Assertions      []Assertion      `json:"assertions"`
	Cleanup         []CleanupStep    `json:"cleanup"`
	Safety          Safety           `json:"safety"`
	EvidenceIDs     []string         `json:"evidence_ids"`
}

type Interface struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Path      string   `json:"path,omitempty"`
	Method    string   `json:"method,omitempty"`
	EntityIDs []string `json:"entity_ids"`
}

type Preconditions struct {
	Authentication string `json:"authentication"`
}

type ValueReference struct {
	Reference string `json:"reference,omitempty"`
	Generated string `json:"generated,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
}

type Step struct {
	Type        string          `json:"type"`
	InterfaceID string          `json:"interface_id,omitempty"`
	Field       string          `json:"field,omitempty"`
	Target      string          `json:"target,omitempty"`
	Value       *ValueReference `json:"value,omitempty"`
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

type Safety struct {
	Classification    string   `json:"classification"`
	Mutating          bool     `json:"mutating"`
	RequiresOwnedData bool     `json:"requires_owned_data"`
	CleanupRequired   bool     `json:"cleanup_required"`
	SelectionScore    int      `json:"selection_score"`
	SelectionReasons  []string `json:"selection_reasons"`
}

type Execution struct {
	SchemaVersion string    `json:"schema_version"`
	ExecutionID   string    `json:"execution_id"`
	PackID        string    `json:"pack_id"`
	Target        string    `json:"target"`
	SelectedIDs   []string  `json:"selected_test_ids"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Results       []Result  `json:"results"`
	Summary       Summary   `json:"summary"`
}

type Result struct {
	TestID          string        `json:"test_id"`
	Mutating        bool          `json:"mutating"`
	Status          string        `json:"status"`
	Reason          string        `json:"reason,omitempty"`
	WorkflowFailure string        `json:"workflow_failure,omitempty"`
	CleanupFailure  string        `json:"cleanup_failure,omitempty"`
	DurationMS      int64         `json:"duration_ms"`
	EvidenceIDs     []string      `json:"evidence_ids"`
	OwnedObjects    []OwnedObject `json:"owned_objects,omitempty"`
}

type OwnedObject struct {
	OwnershipID       string            `json:"ownership_id"`
	ExecutionID       string            `json:"execution_id"`
	EntityID          string            `json:"entity_id"`
	TestID            string            `json:"test_id"`
	RuntimeIdentifier string            `json:"runtime_identifier"`
	GeneratedFields   map[string]string `json:"generated_fields"`
	CleanupStatus     string            `json:"cleanup_status,omitempty"`
}

type Summary struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Blocked       int `json:"blocked"`
	CleanupFailed int `json:"cleanup_failed"`
	Unresolved    int `json:"unresolved"`
	NotRun        int `json:"not_run"`
}

type Evidence struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	TestID      string            `json:"test_id"`
	InterfaceID string            `json:"interface_id,omitempty"`
	Description string            `json:"description"`
	URL         string            `json:"url,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}
