package runtimeverify

import "time"

const SchemaVersion = "0.1"

type RunStatus string

const (
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusPartial   RunStatus = "partial"
	RunStatusFailed    RunStatus = "failed"
)

type Status string

const (
	StatusVerified               Status = "verified"
	StatusPartiallyVerified      Status = "partially_verified"
	StatusUnverified             Status = "unverified"
	StatusNotFound               Status = "not_found"
	StatusAuthRequired           Status = "auth_required"
	StatusRedirected             Status = "redirected"
	StatusRuntimeError           Status = "runtime_error"
	StatusNotAttempted           Status = "not_attempted"
	StatusUnsafe                 Status = "unsafe"
	StatusUnknown                Status = "unknown"
	StatusBlocked                Status = "blocked"
	StatusContradicted           Status = "contradicted"
	StatusRequiresRuntimeBinding Status = "requires_runtime_binding"
)

type Runtime struct {
	SchemaVersion            string                    `json:"schema_version"`
	RuntimeID                string                    `json:"runtime_id"`
	SourceRunID              string                    `json:"source_run_id"`
	SourceGitCommit          string                    `json:"source_git_commit"`
	ApplicationSchemaVersion string                    `json:"application_schema_version"`
	BaseURL                  string                    `json:"base_url"`
	StartedAt                time.Time                 `json:"started_at"`
	CompletedAt              time.Time                 `json:"completed_at"`
	Status                   RunStatus                 `json:"status"`
	Application              ApplicationObservation    `json:"application"`
	Authentication           AuthenticationObservation `json:"authentication"`
	Interfaces               []InterfaceObservation    `json:"interfaces"`
	Features                 []FeatureObservation      `json:"features"`
	ConsoleErrors            []ConsoleObservation      `json:"console_errors"`
	ObservationErrors        []ObservationError        `json:"observation_errors"`
	Failure                  *RuntimeFailure           `json:"failure,omitempty"`
}

type ObservationError struct {
	Phase       string `json:"phase"`
	Operation   string `json:"operation"`
	InterfaceID string `json:"interface_id,omitempty"`
	State       string `json:"state,omitempty"`
	Message     string `json:"message"`
	EvidenceID  string `json:"evidence_id"`
}

type RuntimeFailure struct {
	Phase       string   `json:"phase"`
	Operation   string   `json:"operation"`
	Message     string   `json:"message"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

func MarkFailure(runtime *Runtime, phase, operation, message string, evidenceIDs []string) {
	runtime.Status = RunStatusFailed
	if runtime.Application.Reachable {
		runtime.Status = RunStatusPartial
	}
	runtime.Failure = &RuntimeFailure{
		Phase: phase, Operation: operation, Message: message,
		EvidenceIDs: append([]string(nil), evidenceIDs...),
	}
}

type ApplicationObservation struct {
	Reachable   bool     `json:"reachable"`
	Status      Status   `json:"status"`
	FinalURL    string   `json:"final_url,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	Title       string   `json:"title,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type AuthenticationObservation struct {
	Attempted             bool                     `json:"attempted"`
	Status                Status                   `json:"status"`
	Identity              string                   `json:"identity,omitempty"`
	LoginURL              string                   `json:"login_url,omitempty"`
	FinalURL              string                   `json:"final_url,omitempty"`
	Reason                string                   `json:"reason,omitempty"`
	PrimaryAuthentication Status                   `json:"primary_authentication,omitempty"`
	SecondFactor          *SecondFactorObservation `json:"second_factor,omitempty"`
	EvidenceIDs           []string                 `json:"evidence_ids"`
}

type SecondFactorObservation struct {
	Type      string `json:"type"`
	Attempted bool   `json:"attempted"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type InterfaceObservation struct {
	InterfaceID  string            `json:"interface_id"`
	State        string            `json:"state"`
	Safety       OperationSafety   `json:"safety"`
	Status       Status            `json:"status"`
	Reason       string            `json:"reason,omitempty"`
	RequestedURL string            `json:"requested_url,omitempty"`
	FinalURL     string            `json:"final_url,omitempty"`
	HTTPStatus   int               `json:"http_status,omitempty"`
	Title        string            `json:"title,omitempty"`
	Elements     []SemanticElement `json:"semantic_elements,omitempty"`
	EvidenceIDs  []string          `json:"evidence_ids"`
}

type SemanticElement struct {
	Role string `json:"role,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
}

type FeatureObservation struct {
	FeatureID            string   `json:"feature_id"`
	Status               Status   `json:"status"`
	InterfaceIDs         []string `json:"interface_ids"`
	VerifiedInterfaceIDs []string `json:"verified_interface_ids"`
}

type ConsoleObservation struct {
	InterfaceID string `json:"interface_id,omitempty"`
	State       string `json:"state,omitempty"`
	Message     string `json:"message"`
	EvidenceID  string `json:"evidence_id"`
}

type Summary struct {
	SelectedInterfaces      int
	Observations            int
	SafeInterfacesAttempted int
	Verified                int
	AuthRequired            int
	Contradicted            int
	Redirected              int
	Failed                  int
	SkippedMutating         int
	SkippedUnknown          int
	RequiresBinding         int
}

func Summarize(runtime *Runtime) Summary {
	var result Summary
	selected := map[string]struct{}{}
	for _, item := range runtime.Interfaces {
		if item.State != "not_attempted" {
			selected[item.InterfaceID] = struct{}{}
			result.Observations++
		}
		switch item.Status {
		case StatusVerified:
			result.Verified++
		case StatusAuthRequired:
			result.AuthRequired++
		case StatusRedirected:
			result.Redirected++
		case StatusContradicted:
			result.Contradicted++
			result.Failed++
		case StatusNotFound, StatusRuntimeError:
			result.Failed++
		case StatusRequiresRuntimeBinding:
			result.RequiresBinding++
		case StatusNotAttempted, StatusUnsafe:
			if item.Safety == SafetyMutating {
				result.SkippedMutating++
			} else if item.Safety == SafetyUnknown {
				result.SkippedUnknown++
			}
		}
	}
	result.SelectedInterfaces = len(selected)
	result.SafeInterfacesAttempted = len(selected)
	return result
}
