package tools

import (
	"context"
	"encoding/json"
	"testing"
)

type fakeTool struct{}

func (f fakeTool) Name() string {
	return "fake"
}

func (f fakeTool) Description() string {
	return "fake tool"
}

func (f fakeTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}

func (f fakeTool) Execute(
	ctx context.Context,
	args json.RawMessage,
) (Result, error) {
	return Result{
		Content: json.RawMessage(`{"ok":true}`),
	}, nil
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	if err := registry.Register(fakeTool{}); err != nil {
		t.Fatal(err)
	}

	if _, ok := registry.Get("fake"); !ok {
		t.Fatal("expected fake tool to exist")
	}

	result, err := registry.Execute(
		context.Background(),
		"fake",
		json.RawMessage(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(result.Content) != `{"ok":true}` {
		t.Fatalf("unexpected result: %s", result.Content)
	}
}

func TestDuplicateRegistrationFails(t *testing.T) {
	registry := NewRegistry()

	if err := registry.Register(fakeTool{}); err != nil {
		t.Fatal(err)
	}

	if err := registry.Register(fakeTool{}); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}
