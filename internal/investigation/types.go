package investigation

import (
	"encoding/json"
	"time"
)

type Budget struct {
	MaxTurns         int
	MaxToolCalls     int
	MaxResultRepairs int
	MaxDuration      time.Duration
}

type Task struct {
	ID           string
	Name         string
	Objective    string
	Instructions string

	ToolNames []string

	SubmitSchema json.RawMessage

	ValidateResult ResultValidator

	Budget Budget
}

type Result struct {
	Status     string               `json:"status"`
	Summary    string               `json:"summary"`
	Findings   json.RawMessage      `json:"findings"`
	Claims     []Claim              `json:"claims,omitempty"`
	Unresolved []UnresolvedQuestion `json:"unresolved,omitempty"`
}

type Claim struct {
	Subject     string   `json:"subject"`
	Statement   string   `json:"statement"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type UnresolvedQuestion struct {
	Question               string   `json:"question"`
	Priority               string   `json:"priority"`
	Reason                 string   `json:"reason"`
	SuggestedInvestigation string   `json:"suggested_investigation,omitempty"`
	EvidenceIDs            []string `json:"evidence_ids,omitempty"`
}

type EvidenceLookup interface {
	Exists(id string) bool
}

type ResultValidator func(
	result *Result,
	evidence EvidenceLookup,
) error
