package runtimeverify

import (
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

func TestSafeMutatingAndUnknownClassification(t *testing.T) {
	tests := []struct {
		name string
		item surface.Interface
		want OperationSafety
	}{
		{"web view", surface.Interface{ID: "web.projects.list", Type: "web_page", Locator: surface.InterfaceLocator{Method: "GET", Path: "/projects"}}, SafetySafe},
		{"form action", surface.Interface{ID: "web.task.create", Type: "form_action", Locator: surface.InterfaceLocator{Method: "POST", Path: "/task"}}, SafetyMutating},
		{"mutating semantic beats GET", surface.Interface{ID: "web.user.delete", Type: "web_page", Name: "Delete user", Locator: surface.InterfaceLocator{Method: "GET", Path: "/delete"}}, SafetyMutating},
		{"read API", surface.Interface{ID: "api.task.get", Type: "api_endpoint", Locator: surface.InterfaceLocator{MethodName: "getTask"}}, SafetySafe},
		{"CLI", surface.Interface{ID: "cli.inspect", Type: "cli_command", Locator: surface.InterfaceLocator{Command: "inspect"}}, SafetyUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyInterface(test.item).Safety; got != test.want {
				t.Fatalf("classification = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBrowserNavigableRequiresSafeConcreteURL(t *testing.T) {
	item := surface.Interface{ID: "web.projects", Type: "web_page", Locator: surface.InterfaceLocator{Path: "/projects"}}
	if !BrowserNavigable(item, ClassifyInterface(item)) {
		t.Fatal("safe page was not browser navigable")
	}
	item.Type = "form_action"
	if BrowserNavigable(item, ClassifyInterface(item)) {
		t.Fatal("form action was browser navigable")
	}
}

func TestVerificationPriorityIsDeterministicAndPrefersBoundedAcceptanceTargets(t *testing.T) {
	root := surface.Interface{ID: "web.root", Type: "web_page", Locator: surface.InterfaceLocator{Path: "/"}}
	health := surface.Interface{ID: "web.health", Type: "web_page", Name: "Health", Locator: surface.InterfaceLocator{Path: "/health"}}
	public := surface.Interface{ID: "web.board", Type: "web_page", Locator: surface.InterfaceLocator{Path: "/board"}, Access: &surface.Access{Authentication: "not_required"}}
	view := surface.Interface{ID: "web.task.view", Type: "web_page", Name: "View task", Locator: surface.InterfaceLocator{Path: "/task"}}
	if !(verificationPriority(root) < verificationPriority(health) &&
		verificationPriority(health) < verificationPriority(public) &&
		verificationPriority(public) < verificationPriority(view)) {
		t.Fatal("bounded verification priorities are not stable")
	}
}
