package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

type Registry struct {
	tools map[string]Tool
}

func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
	}
}

func (r *Registry) Register(tool Tool) error {
	name := tool.Name()

	if name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool already registered: %s", name)
	}

	r.tools[name] = tool
	return nil
}

func (r *Registry) Get(name string) (Tool, bool) {
	tool, ok := r.tools[name]
	return tool, ok
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.tools))

	for name := range r.tools {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

func (r *Registry) Execute(
	ctx context.Context,
	name string,
	args json.RawMessage,
) (Result, error) {
	tool, ok := r.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("unknown tool: %s", name)
	}

	return tool.Execute(ctx, args)
}
