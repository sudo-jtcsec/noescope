package features

type Access struct {
	Authentication string   `json:"authentication"`
	RoleIDs        []string `json:"role_ids"`
	PermissionIDs  []string `json:"permission_ids"`
}

type SourceComponent struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol,omitempty"`
}

type Node struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Description      string            `json:"description"`
	Access           Access            `json:"access"`
	EntityIDs        []string          `json:"entity_ids"`
	InterfaceIDs     []string          `json:"interface_ids"`
	SourceComponents []SourceComponent `json:"source_components,omitempty"`
	Children         []Node            `json:"children"`
	Confidence       float64           `json:"confidence"`
	EvidenceIDs      []string          `json:"evidence_ids"`
}

type Findings struct {
	Features []Node `json:"features"`
}

// Counts returns the number of root module nodes and all nodes in the tree.
// Counting is deterministic and independent of model-provided summaries.
func Counts(findings *Findings) (topLevelModules int, totalNodes int) {
	if findings == nil {
		return 0, 0
	}
	for _, node := range findings.Features {
		if node.Type == "module" {
			topLevelModules++
		}
		totalNodes += countNode(node)
	}
	return topLevelModules, totalNodes
}

func countNode(node Node) int {
	total := 1
	for _, child := range node.Children {
		total += countNode(child)
	}
	return total
}
