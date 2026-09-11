package surface

type InterfaceLocator struct {
	Path          string `json:"path,omitempty"`
	Method        string `json:"method,omitempty"`
	Command       string `json:"command,omitempty"`
	Schedule      string `json:"schedule,omitempty"`
	Event         string `json:"event,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	MethodName    string `json:"method_name,omitempty"`
	TransportPath string `json:"transport_path,omitempty"`
}

type Access struct {
	Authentication string   `json:"authentication"`
	RoleIDs        []string `json:"role_ids"`
	PermissionIDs  []string `json:"permission_ids"`
	Confidence     float64  `json:"confidence"`
	EvidenceIDs    []string `json:"evidence_ids"`
}

type SourceComponent struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol,omitempty"`
}

type IntegrationLocator struct {
	BaseURL string `json:"base_url,omitempty"`
	Path    string `json:"path,omitempty"`
	Method  string `json:"method,omitempty"`
	Name    string `json:"name,omitempty"`
	Command string `json:"command,omitempty"`
}

type IntegrationAuthentication struct {
	Type             string `json:"type"`
	CredentialSource string `json:"credential_source,omitempty"`
}

type Interface struct {
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Locator          InterfaceLocator  `json:"locator"`
	Access           *Access           `json:"access,omitempty"`
	InputNames       []string          `json:"input_names,omitempty"`
	EntityIDs        []string          `json:"entity_ids"`
	SourceComponents []SourceComponent `json:"source_components"`
	Confidence       float64           `json:"confidence"`
	EvidenceIDs      []string          `json:"evidence_ids"`
}

type Integration struct {
	ID               string                    `json:"id"`
	Type             string                    `json:"type"`
	Name             string                    `json:"name"`
	Description      string                    `json:"description"`
	Locator          IntegrationLocator        `json:"locator"`
	Authentication   IntegrationAuthentication `json:"authentication"`
	EntityIDs        []string                  `json:"entity_ids"`
	SourceComponents []SourceComponent         `json:"source_components"`
	Confidence       float64                   `json:"confidence"`
	EvidenceIDs      []string                  `json:"evidence_ids"`
}

type Handler struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Symbol       string   `json:"symbol,omitempty"`
	InterfaceIDs []string `json:"interface_ids"`
	Confidence   float64  `json:"confidence"`
	EvidenceIDs  []string `json:"evidence_ids"`
}

type Relationship struct {
	Type            string   `json:"type"`
	FromInterfaceID string   `json:"from_interface_id"`
	ToInterfaceID   string   `json:"to_interface_id,omitempty"`
	ToIntegrationID string   `json:"to_integration_id,omitempty"`
	Description     string   `json:"description"`
	Confidence      float64  `json:"confidence"`
	EvidenceIDs     []string `json:"evidence_ids"`
}

type Findings struct {
	Interfaces    []Interface    `json:"interfaces"`
	Integrations  []Integration  `json:"integrations"`
	Handlers      []Handler      `json:"handlers"`
	Relationships []Relationship `json:"relationships"`
	Coverage      Coverage       `json:"coverage"`
}

type Coverage struct {
	Web          CategoryCoverage `json:"web"`
	API          CategoryCoverage `json:"api"`
	CLI          CategoryCoverage `json:"cli"`
	Background   CategoryCoverage `json:"background"`
	Integrations CategoryCoverage `json:"integrations"`
}

type CategoryCoverage struct {
	Applicable   bool   `json:"applicable"`
	Status       string `json:"status"`
	Interfaces   int    `json:"interfaces"`
	Integrations int    `json:"integrations"`
}
