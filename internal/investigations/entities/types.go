package entities

type SourceComponent struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol,omitempty"`
}

type Persistence struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Relationship struct {
	Type           string   `json:"type"`
	TargetEntityID string   `json:"target_entity_id"`
	Description    string   `json:"description"`
	Confidence     float64  `json:"confidence"`
	EvidenceIDs    []string `json:"evidence_ids"`
}

type Entity struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Aliases          []string          `json:"aliases"`
	SourceComponents []SourceComponent `json:"source_components"`
	Persistence      []Persistence     `json:"persistence"`
	Relationships    []Relationship    `json:"relationships"`
	Confidence       float64           `json:"confidence"`
	EvidenceIDs      []string          `json:"evidence_ids"`
}

type Findings struct {
	Entities []Entity `json:"entities"`
}
