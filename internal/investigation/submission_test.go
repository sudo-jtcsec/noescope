package investigation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/llm"
)

func TestParseSubmittedResultAcceptsCanonicalObject(t *testing.T) {
	result, shape, err := parseSubmittedResult([]byte(
		`{"status":"completed","summary":"x","findings":{}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || shape.Type != "object" {
		t.Fatalf("unexpected parsed result or shape: %#v %#v", result, shape)
	}
}

func TestParseSubmittedResultRejectsWrapperWithUsefulShape(t *testing.T) {
	_, shape, err := parseSubmittedResult([]byte(`{"result":"hidden"}`))
	if err == nil || !strings.Contains(
		err.Error(),
		"expected fields status, summary, findings; got keys [result]",
	) {
		t.Fatalf("unexpected wrapper error: %v", err)
	}
	if shape.Summary() != "bytes=19 type=object keys=[result]" {
		t.Fatalf("unexpected shape summary: %s", shape.Summary())
	}
	if shape.FieldSummary() != "result=string" {
		t.Fatalf("unexpected field summary: %s", shape.FieldSummary())
	}
}

func TestParseSubmittedResultIdentifiesMissingFields(t *testing.T) {
	_, _, err := parseSubmittedResult([]byte(`{"summary":"x"}`))
	if err == nil || !strings.Contains(
		err.Error(),
		"expected fields status, summary, findings; got keys [summary]",
	) {
		t.Fatalf("unexpected missing-fields error: %v", err)
	}
}

func TestParseSubmittedResultRejectsStringTopLevel(t *testing.T) {
	_, shape, err := parseSubmittedResult([]byte(`"{\"status\":\"completed\"}"`))
	if err == nil || !strings.Contains(
		err.Error(),
		"submit result: expected object, got string",
	) {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if shape.Type != "string" {
		t.Fatalf("unexpected top-level shape: %#v", shape)
	}
}

func TestRejectedSubmissionDiagnosticsNeverIncludeValues(t *testing.T) {
	const secret = "diagnostic-secret-value"
	logs := make([]string, 0)
	runner := &Runner{
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}

	_, err := runner.validateSubmission(Task{ID: "architecture"}, llm.ToolCall{
		Function: llm.FunctionCall{
			Name:      submitToolName,
			Arguments: `{"result":"diagnostic-secret-value"}`,
		},
	})
	if err == nil {
		t.Fatal("expected rejected wrapper")
	}

	joined := strings.Join(logs, "\n")
	for _, expected := range []string{
		"[architecture] rejected submission shape: bytes=36 type=object keys=[result]",
		"[architecture] submission fields: result=string",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing diagnostic %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, secret) {
		t.Fatalf("diagnostic exposed a value:\n%s", joined)
	}
}
