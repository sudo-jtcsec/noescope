package architecture

type Technology struct {
	Name        string   `json:"name"`
	Role        string   `json:"role,omitempty"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Statement struct {
	Value       string   `json:"value"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Entrypoint struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	Purpose     string   `json:"purpose"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Directory struct {
	Path        string   `json:"path"`
	Purpose     string   `json:"purpose"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Findings struct {
	Languages            []Technology `json:"languages"`
	Formats              []Technology `json:"formats"`
	Frameworks           []Technology `json:"frameworks"`
	Libraries            []Technology `json:"libraries"`
	Databases            []Technology `json:"databases"`
	WebServers           []Technology `json:"web_servers"`
	ExternalInterfaces   []Technology `json:"external_interfaces"`
	ArchitectureStyle    Statement    `json:"architecture_style"`
	Entrypoints          []Entrypoint `json:"entrypoints"`
	ImportantDirectories []Directory  `json:"important_directories"`
}
