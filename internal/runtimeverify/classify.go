package runtimeverify

import (
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

type OperationSafety string

const (
	SafetySafe     OperationSafety = "safe"
	SafetyMutating OperationSafety = "mutating"
	SafetyUnknown  OperationSafety = "unknown"
)

type SafetyClassification struct {
	Safety OperationSafety
	Reason string
}

func ClassifyInterface(item surface.Interface) SafetyClassification {
	method := strings.ToUpper(strings.TrimSpace(item.Locator.Method))
	semantic := strings.ToLower(strings.Join([]string{
		item.ID, item.Name, item.Description, item.Locator.MethodName,
		item.Locator.Command, item.Locator.Event,
	}, " "))
	if item.Type == "form_action" || containsWord(semantic, mutatingWords) {
		return SafetyClassification{SafetyMutating, "source metadata describes a state-changing operation"}
	}
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return SafetyClassification{SafetyMutating, "HTTP method is state-changing"}
	}
	switch item.Type {
	case "scheduled_job", "worker", "event_consumer":
		return SafetyClassification{SafetyMutating, "background invocation may change application state"}
	case "web_page":
		if method == "" || method == "GET" || method == "HEAD" {
			return SafetyClassification{SafetySafe, "read-only web page"}
		}
	case "api_endpoint":
		if (method == "GET" || method == "HEAD") && item.Locator.Path != "" {
			return SafetyClassification{SafetySafe, "read-only HTTP endpoint"}
		}
		if containsWord(semantic, readOnlyWords) {
			return SafetyClassification{SafetySafe, "source metadata describes a read-only operation"}
		}
	case "cli_command", "script":
		return SafetyClassification{SafetyUnknown, "CLI and script interfaces are outside browser verification"}
	}
	if containsWord(semantic, readOnlyWords) {
		return SafetyClassification{SafetySafe, "source metadata describes a read-only operation"}
	}
	return SafetyClassification{SafetyUnknown, "source metadata is insufficient to prove read-only behavior"}
}

func BrowserNavigable(item surface.Interface, classification SafetyClassification) bool {
	if classification.Safety != SafetySafe {
		return false
	}
	if item.Type == "web_page" {
		return item.Locator.Path != "" || item.Locator.TransportPath != ""
	}
	method := strings.ToUpper(strings.TrimSpace(item.Locator.Method))
	return item.Type == "api_endpoint" && item.Locator.Path != "" &&
		(method == "GET" || method == "HEAD")
}

var mutatingWords = []string{
	"create", "add", "update", "edit", "delete", "remove", "upload", "write",
	"save", "submit", "close", "reopen", "move", "enable", "disable", "reset",
	"install", "uninstall", "upgrade", "trigger", "start", "stop", "pause", "resume",
}

var readOnlyWords = []string{
	"get", "list", "view", "show", "search", "find", "read", "status", "health",
	"count", "download", "export", "isactive", "details", "version",
}

func containsWord(value string, words []string) bool {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	for _, field := range fields {
		for _, word := range words {
			if field == word || strings.HasPrefix(field, word) {
				return true
			}
		}
	}
	return false
}
