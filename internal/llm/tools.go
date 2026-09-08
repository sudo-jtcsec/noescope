package llm

import "github.com/sudo-jtcsec/noescope/internal/tools"

func ToolDefinitions(
	registry *tools.Registry,
	names []string,
) []ToolDefinition {
	definitions := make([]ToolDefinition, 0, len(names))

	for _, name := range names {
		tool, ok := registry.Get(name)
		if !ok {
			continue
		}

		definitions = append(definitions, ToolDefinition{
			Type: "function",
			Function: FunctionDefinition{
				Name:        tool.Name(),
				Description: tool.Description(),
				Parameters:  tool.Schema(),
			},
		})
	}

	return definitions
}
