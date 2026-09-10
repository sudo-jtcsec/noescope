package authorization

type Model struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Inherits    []string `json:"inherits"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Permission struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type RolePermission struct {
	RoleID        string   `json:"role_id"`
	PermissionIDs []string `json:"permission_ids"`
	Confidence    float64  `json:"confidence"`
	EvidenceIDs   []string `json:"evidence_ids"`
}

type Enforcement struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Symbol      string   `json:"symbol,omitempty"`
	Description string   `json:"description"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Findings struct {
	AuthorizationPresent bool             `json:"authorization_present"`
	Confidence           float64          `json:"confidence"`
	EvidenceIDs          []string         `json:"evidence_ids"`
	Model                *Model           `json:"model,omitempty"`
	Roles                []Role           `json:"roles"`
	Permissions          []Permission     `json:"permissions"`
	RolePermissions      []RolePermission `json:"role_permissions"`
	Enforcement          []Enforcement    `json:"enforcement"`
}
