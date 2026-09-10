package authentication

type Session struct {
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Storage string `json:"storage,omitempty"`
}

type Logout struct {
	Entrypoints []string `json:"entrypoints"`
	Behavior    string   `json:"behavior"`
}

type Mechanism struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	LoginEntrypoints []string `json:"login_entrypoints"`
	CredentialFields []string `json:"credential_fields"`
	Session          *Session `json:"session,omitempty"`
	EstablishedBy    []string `json:"established_by"`
	CheckedBy        []string `json:"checked_by"`
	Logout           *Logout  `json:"logout,omitempty"`
	SourceComponents []string `json:"source_components"`
	Confidence       float64  `json:"confidence"`
	EvidenceIDs      []string `json:"evidence_ids"`
}

type Findings struct {
	AuthenticationPresent bool        `json:"authentication_present"`
	Confidence            float64     `json:"confidence"`
	EvidenceIDs           []string    `json:"evidence_ids"`
	Mechanisms            []Mechanism `json:"mechanisms"`
}
