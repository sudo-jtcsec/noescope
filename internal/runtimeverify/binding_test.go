package runtimeverify

import "testing"

func TestParameterizedRouteRequiresObservedBinding(t *testing.T) {
	result, err := ResolveRoute("https://app.example/", "/project/{project_id}", &DiscoveryState{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RequiresBinding || result.URL != "" {
		t.Fatalf("unexpected unresolved route: %#v", result)
	}
}

func TestParameterizedRouteBindsFromObservedSameOriginLink(t *testing.T) {
	state := &DiscoveryState{Links: []ObservedLink{
		{URL: "https://external.example/project/9", EvidenceID: "external"},
		{URL: "https://app.example/project/4", EvidenceID: "ev_list"},
	}}
	result, err := ResolveRoute("https://app.example/", "/project/{project_id}", state)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequiresBinding || result.URL != "https://app.example/project/4" ||
		result.Bindings["project_id"] != "4" || len(result.EvidenceIDs) != 1 ||
		result.EvidenceIDs[0] != "ev_list" {
		t.Fatalf("unexpected route binding: %#v", result)
	}
}

func TestResolveRouteRejectsExternalInterfaceURL(t *testing.T) {
	if _, err := ResolveRoute("https://app.example/", "https://external.example/path", nil); err == nil {
		t.Fatal("external interface URL was accepted")
	}
}

func TestParameterizedRelativeRouteRespectsBasePath(t *testing.T) {
	state := &DiscoveryState{Links: []ObservedLink{{
		URL: "https://app.example/kanboard/project/4", EvidenceID: "ev_list",
	}}}
	result, err := ResolveRoute("https://app.example/kanboard/", "project/{project_id}", state)
	if err != nil {
		t.Fatal(err)
	}
	if result.URL != "https://app.example/kanboard/project/4" || result.Bindings["project_id"] != "4" {
		t.Fatalf("relative parameterized route resolved incorrectly: %#v", result)
	}
}
