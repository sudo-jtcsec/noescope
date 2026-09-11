package features

import (
	"reflect"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

func TestCountInterfaceMappingsClassifiesConcreteRootOnlyAndUnmappedActions(t *testing.T) {
	surfaceFindings := &surface.Findings{Interfaces: []surface.Interface{
		{
			ID: "api.transport", Type: "api_endpoint",
			Locator: surface.InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/rpc"},
		},
		{
			ID: "api.task.create", Type: "api_endpoint",
			Locator: surface.InterfaceLocator{MethodName: "task.create", TransportPath: "/rpc"},
		},
		{
			ID: "cli.root", Type: "cli_command",
			Locator: surface.InterfaceLocator{Command: "app"},
		},
	}}
	findings := &Findings{Features: []Node{{
		ID: "tasks", Type: "module", Children: []Node{
			{ID: "tasks.create", Type: "action", InterfaceIDs: []string{"api.task.create"}},
			{ID: "tasks.transport", Type: "action", InterfaceIDs: []string{"api.transport", "cli.root"}},
			{ID: "tasks.review", Type: "action", InterfaceIDs: []string{}},
		},
	}}}

	got := CountInterfaceMappings(findings, surfaceFindings)
	want := InterfaceMappingCounts{ConcreteActions: 1, RootOnlyActions: 1, UnmappedActions: 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapping counts = %#v, want %#v", got, want)
	}
}

func TestIsRootInterfaceUsesGenericSurfaceMetadata(t *testing.T) {
	tests := []struct {
		item surface.Interface
		root bool
	}{
		{surface.Interface{
			ID: "api.transport", Type: "api_endpoint",
			Locator: surface.InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/rpc"},
		}, true},
		{surface.Interface{
			ID: "api.task.create", Type: "api_endpoint",
			Locator: surface.InterfaceLocator{Protocol: "jsonrpc", MethodName: "task.create", TransportPath: "/rpc"},
		}, false},
		{surface.Interface{
			ID: "cli.root", Type: "cli_command",
			Locator: surface.InterfaceLocator{Command: "app"},
		}, true},
	}
	for _, test := range tests {
		if got := IsRootInterface(test.item); got != test.root {
			t.Fatalf("IsRootInterface(%q) = %v, want %v", test.item.ID, got, test.root)
		}
	}
}

func TestOperationCandidateClassificationIncludesViewsAndCommandsButExcludesRoots(t *testing.T) {
	findings := &surface.Findings{Interfaces: []surface.Interface{
		{ID: "web.projects", Type: "web_page", Locator: surface.InterfaceLocator{Path: "/projects"}},
		{ID: "api.task.create", Type: "api_endpoint", Locator: surface.InterfaceLocator{MethodName: "task.create"}},
		{ID: "cli.migrate", Type: "cli_command", Locator: surface.InterfaceLocator{Command: "migrate"}},
		{ID: "api.transport", Type: "api_endpoint", Locator: surface.InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/rpc"}},
	}}
	want := []string{"api.task.create", "cli.migrate", "web.projects"}
	if got := ConcreteCandidateInterfaceIDs(findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("operation candidates = %v, want %v", got, want)
	}
}

func TestCountConcreteInterfaceCoverageIsDeterministic(t *testing.T) {
	surfaceFindings := &surface.Findings{Interfaces: []surface.Interface{
		{ID: "api.task.create", Type: "api_endpoint", Locator: surface.InterfaceLocator{MethodName: "task.create"}},
		{ID: "api.task.update", Type: "api_endpoint", Locator: surface.InterfaceLocator{MethodName: "task.update"}},
		{ID: "api.transport", Type: "api_endpoint", Locator: surface.InterfaceLocator{Protocol: "jsonrpc", TransportPath: "/rpc"}},
	}}
	findings := &Findings{Features: []Node{{
		ID: "tasks", Type: "module", InterfaceIDs: []string{"api.task.create", "api.transport"},
	}}}
	want := ConcreteInterfaceCoverageCounts{
		CandidateInterfaces: 2, ReferencedInterfaces: 1, UnreferencedInterfaces: 1,
	}
	if got := CountConcreteInterfaceCoverage(findings, surfaceFindings); !reflect.DeepEqual(got, want) {
		t.Fatalf("coverage = %#v, want %#v", got, want)
	}
}
