package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

func TestRunnerIncludesTaskContextInPrompt(t *testing.T) {
	requests := make(chan llm.ChatRequest, 1)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request llm.ChatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			requests <- request
			w.Header().Set("Content-Type", "application/json")

			_ = json.NewEncoder(w).Encode(llm.ChatResponse{
				Choices: []llm.Choice{
					{
						Message: llm.Message{
							Role:    "assistant",
							Content: `{"status":"completed","summary":"done","findings":{"authentication_present":false,"confidence":0,"evidence_ids":[],"mechanisms":[]}}`,
						},
					},
				},
			})
		}),
	)
	defer server.Close()

	runner := NewRunner(
		llm.NewClient(server.URL, "", "test-model"),
		tools.NewRegistry(),
		evidence.NewStore(t.TempDir()),
	)

	_, err := runner.Run(context.Background(), Task{
		ID:        "authentication",
		Objective: "Investigate authentication.",
		Context: json.RawMessage(`{
          "frameworks": [{"name": "net/http"}],
          "entrypoints": [{"path": "cmd/server/main.go"}]
        }`),
		SubmitSchema: json.RawMessage(`{"type":"object"}`),
		Budget: Budget{
			MaxTurns:      1,
			FinalizeTurns: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := <-requests
	if len(request.Messages) != 3 {
		t.Fatalf(
			"expected system, task, and finalization messages, got %d",
			len(request.Messages),
		)
	}

	systemPrompt := request.Messages[0].Content
	if !strings.Contains(
		systemPrompt,
		"Previously validated Noescope findings (structured JSON)",
	) {
		t.Fatal("context label was not included in the system prompt")
	}

	if !strings.Contains(systemPrompt, `"cmd/server/main.go"`) {
		t.Fatal("structured task context was not included in the system prompt")
	}

	if !strings.Contains(
		systemPrompt,
		"Summary is human-readable narrative only",
	) {
		t.Fatal("system prompt does not identify Summary as non-canonical")
	}

	if request.Messages[1].Content != "Investigate authentication." {
		t.Fatalf(
			"unexpected objective message: %q",
			request.Messages[1].Content,
		)
	}
}

func TestRunnerSendsStructuredSchemaAsJSONObject(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_submit", validSubmissionArguments),
	})
	defer server.Close()

	schema := json.RawMessage(`{
      "type": "object",
      "properties": {
        "findings": {
          "type": "object",
          "properties": {"ok": {"type": "boolean"}}
        }
      }
    }`)
	task := repairTestTask(Budget{
		MaxTurns:      1,
		FinalizeTurns: 1,
	})
	task.SubmitSchema = schema

	runner := testRunner(t, server.URL, tools.NewRegistry())
	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 1 || len(requests[0].Tools) != 0 {
		t.Fatalf("unexpected request/tool count: %#v", requests)
	}
	if requests[0].ToolChoice != nil {
		t.Fatalf("structured finalization sent tool_choice: %#v", requests[0].ToolChoice)
	}
	if requests[0].ResponseFormat == nil ||
		requests[0].ResponseFormat.Type != "json_schema" {
		t.Fatalf("missing JSON Schema response format: %#v", requests[0].ResponseFormat)
	}
	parameters := requests[0].ResponseFormat.JSONSchema.Schema
	if JSONValueKind(parameters) != "object" {
		t.Fatalf("response schema was not sent as an object: %s", parameters)
	}

	var decoded struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(parameters, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Properties["findings"].Type != "object" {
		t.Fatalf(
			"findings schema type was %q",
			decoded.Properties["findings"].Type,
		)
	}
}

func TestRunnerUsesAutoToolsThenToolFreeStructuredFinalizationAndRepair(t *testing.T) {
	registry := tools.NewRegistry()
	executions := 0
	if err := registry.Register(&countingTool{executions: &executions}); err != nil {
		t.Fatal(err)
	}
	server := newScriptedLLMServer(t, []llm.Message{
		{Role: "assistant", Content: "investigating"},
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, registry)
	task := repairTestTask(Budget{
		MaxTurns:           2,
		FinalizeTurns:      1,
		MaxSemanticRepairs: 1,
	})
	task.ToolNames = []string{"repository_test_tool"}
	if _, err := runner.Run(
		context.Background(),
		task,
	); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 3 {
		t.Fatalf("expected normal, finalization, and repair calls; got %d", len(requests))
	}
	if requests[0].ToolChoice != "auto" {
		t.Fatalf("normal tool choice was %#v", requests[0].ToolChoice)
	}
	assertStructuredRequest(t, requests[1])
	assertStructuredRequest(t, requests[2])
}

func TestRunnerNormalizesDoubleEncodedFindingsWithoutRepair(t *testing.T) {
	const sensitiveValue = "normalization-secret-marker"
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage(
			"call_submit",
			`{"status":"completed","summary":"done","findings":"{\"ok\":true,\"sensitive\":\"normalization-secret-marker\"}"}`,
		),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	task := repairTestTask(Budget{
		MaxTurns:           1,
		FinalizeTurns:      1,
		MaxSemanticRepairs: 1,
	})
	task.ValidateResult = func(result *Result, evidence EvidenceLookup) error {
		var findings struct {
			OK bool `json:"ok"`
		}
		if err := DecodeObjectFindings(
			result.Findings,
			&findings,
			"test findings",
		); err != nil {
			return err
		}
		if !findings.OK {
			return errors.New("normalized findings did not validate")
		}
		return nil
	}

	result, err := runner.Run(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if JSONValueKind(result.Findings) != "object" {
		t.Fatalf("returned findings were not normalized: %s", result.Findings)
	}
	if len(server.Requests()) != 1 {
		t.Fatalf("successful normalization used a repair call")
	}

	joinedLogs := strings.Join(logs, "\n")
	if !strings.Contains(
		joinedLogs,
		"[repair-test] normalized double-encoded findings object",
	) {
		t.Fatalf("normalization was not logged:\n%s", joinedLogs)
	}
	if strings.Contains(joinedLogs, sensitiveValue) {
		t.Fatalf("normalization log exposed findings contents:\n%s", joinedLogs)
	}
}

func TestRunnerRepairsSemanticFailureAfterNormalization(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage(
			"call_bad",
			`{"status":"completed","summary":"done","findings":"{}"}`,
		),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	if _, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 1,
		}),
	); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 2 {
		t.Fatalf("expected one submission and one repair, got %d", len(requests))
	}
	assertStructuredRequest(t, requests[1])
}

func TestRunnerUsesIndependentFormatAndSemanticRepairBudgets(t *testing.T) {
	const malformed = `{"status":"completed","summary":"done","findings":"not-json"}`
	const unsupported = `{"status":"completed","summary":"done","findings":{"evidence_ids":[]}}`
	const supported = `{"status":"completed","summary":"done","findings":{"evidence_ids":["ev_language"]}}`
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_initial", malformed),
		submissionMessage("call_format_1", malformed),
		submissionMessage("call_format_2", unsupported),
		submissionMessage("call_semantic_1", supported),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	task := Task{
		ID:           "architecture",
		Objective:    "Test independent repair budgets.",
		SubmitSchema: json.RawMessage(`{"type":"object"}`),
		ValidateResult: func(result *Result, evidence EvidenceLookup) error {
			var findings struct {
				EvidenceIDs []string `json:"evidence_ids"`
			}
			if err := DecodeObjectFindings(
				result.Findings,
				&findings,
				"architecture findings",
			); err != nil {
				return NewSubmissionFormatError(err)
			}
			if len(findings.EvidenceIDs) == 0 {
				return errors.New(
					`languages[2] "JavaScript" has confidence 0.70 but no evidence`,
				)
			}
			return nil
		},
		Budget: Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxFormatRepairs:   2,
			MaxSemanticRepairs: 2,
		},
	}

	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 4 {
		t.Fatalf("expected initial plus three repairs, got %d", len(requests))
	}
	for i := 1; i < len(requests); i++ {
		assertStructuredRequest(t, requests[i])
		if size := estimateMessageBytes(requests[i].Messages); size > contextMessageByteBudget {
			t.Fatalf("repair request %d exceeded context budget: %d", i, size)
		}
	}
	if !requestContains(requests[1], "structurally invalid") {
		t.Fatal("format repair prompt was not used")
	}
	if !requestContains(requests[3], "failed validation") {
		t.Fatal("semantic repair prompt was not used")
	}

	joined := strings.Join(logs, "\n")
	for _, expected := range []string{
		"[architecture] format error: findings: JSON string does not contain valid JSON",
		"[architecture] format repair attempt 1/2",
		"[architecture] format repair attempt 2/2",
		`[architecture] validation error: languages[2] "JavaScript" has confidence 0.70 but no evidence`,
		"[architecture] semantic repair attempt 1/2",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing log %q:\n%s", expected, joined)
		}
	}
}

func TestRunnerFailsAfterMaximumFormatRepairs(t *testing.T) {
	const malformed = `{"status":"completed","summary":"done","findings":"not-json"}`
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_initial", malformed),
		submissionMessage("call_format_1", malformed),
		submissionMessage("call_format_2", malformed),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	_, err := runner.Run(context.Background(), Task{
		ID:           "format-test",
		Objective:    "Test format repair exhaustion.",
		SubmitSchema: json.RawMessage(`{"type":"object"}`),
		Budget: Budget{
			MaxTurns:         1,
			FinalizeTurns:    1,
			MaxFormatRepairs: 2,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeded format repair limit") {
		t.Fatalf("expected format repair limit error, got %v", err)
	}
	if len(server.Requests()) != 3 {
		t.Fatalf("expected initial plus two format repairs")
	}
}

func TestRunnerSemanticErrorDoesNotConsumeFormatBudget(t *testing.T) {
	const malformed = `{"status":"completed","summary":"done","findings":"not-json"}`
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_semantic", invalidSubmissionArguments),
		submissionMessage("call_format", malformed),
		submissionMessage("call_valid", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	if _, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxFormatRepairs:   1,
			MaxSemanticRepairs: 1,
		}),
	); err != nil {
		t.Fatal(err)
	}
	if len(server.Requests()) != 3 {
		t.Fatalf("expected independent semantic and format repairs")
	}
}

func TestRunnerLogsRejectedResultAndRepairAttempt(t *testing.T) {
	responses := 0
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			responses++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(llm.ChatResponse{
				Choices: []llm.Choice{
					{
						Message: llm.Message{
							Role:    "assistant",
							Content: `{"status":"completed","summary":"done","findings":{}}`,
						},
					},
				},
			})
		}),
	)
	defer server.Close()

	runner := NewRunner(
		llm.NewClient(server.URL, "", "test-model"),
		tools.NewRegistry(),
		evidence.NewStore(t.TempDir()),
	)

	validationCalls := 0
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	_, err := runner.Run(context.Background(), Task{
		ID:           "architecture",
		Objective:    "Test repair logging.",
		SubmitSchema: json.RawMessage(`{"type":"object"}`),
		ValidateResult: func(
			result *Result,
			evidence EvidenceLookup,
		) error {
			validationCalls++
			if validationCalls == 1 {
				return errors.New(
					"important_directories[4] has confidence 0.80 but no evidence",
				)
			}
			return nil
		},
		Budget: Budget{
			MaxTurns:           1,
			MaxSemanticRepairs: 2,
			FinalizeTurns:      1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if responses != 2 {
		t.Fatalf("expected finalization and one repair response, got %d", responses)
	}

	joinedLogs := strings.Join(logs, "\n")
	for _, expected := range []string{
		"[architecture] validation error: important_directories[4] has confidence 0.80 but no evidence",
		"[architecture] semantic repair attempt 1/2",
	} {
		if !strings.Contains(joinedLogs, expected) {
			t.Fatalf("logs do not contain %q:\n%s", expected, joinedLogs)
		}
	}
}

func TestRunnerAcceptsValidResultOnFinalNormalTurn(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		{Role: "assistant", Content: "investigating"},
		{Role: "assistant", Content: "still investigating"},
		submissionMessage("call_final", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	result, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           3,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 2,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Findings) != `{"ok":true}` {
		t.Fatalf("unexpected findings: %s", result.Findings)
	}
	if len(server.Requests()) != 3 {
		t.Fatalf("expected three normal model turns, got %d", len(server.Requests()))
	}
}

func TestRunnerRepairsRejectedFinalTurnBeyondMaxTurns(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		{Role: "assistant", Content: "investigating"},
		{Role: "assistant", Content: "still investigating"},
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	if _, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           3,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 1,
		}),
	); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 4 {
		t.Fatalf("expected repair call beyond three normal turns, got %d calls", len(requests))
	}
	assertStructuredRequest(t, requests[3])
}

func TestRunnerSucceedsAfterOneRejectedResult(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	if _, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 1,
		}),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerSucceedsOnSecondRepair(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair_1", invalidSubmissionArguments),
		submissionMessage("call_repair_2", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if _, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 2,
		}),
	); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 3 {
		t.Fatalf("expected one normal and two repair calls, got %d", len(requests))
	}
	assertStructuredRequest(t, requests[1])
	assertStructuredRequest(t, requests[2])

	joinedLogs := strings.Join(logs, "\n")
	for _, expected := range []string{
		"[repair-test] semantic repair attempt 1/2",
		"[repair-test] semantic repair attempt 2/2",
	} {
		if !strings.Contains(joinedLogs, expected) {
			t.Fatalf("repair logs do not contain %q:\n%s", expected, joinedLogs)
		}
	}
}

func TestRunnerFailsAfterMaximumSemanticRepairs(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair_1", invalidSubmissionArguments),
		submissionMessage("call_repair_2", invalidSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	_, err := runner.Run(
		context.Background(),
		repairTestTask(Budget{
			MaxTurns:           1,
			FinalizeTurns:      1,
			MaxSemanticRepairs: 2,
		}),
	)
	if err == nil || !strings.Contains(err.Error(), "exceeded semantic repair limit") {
		t.Fatalf("expected clean repair limit error, got %v", err)
	}
	if len(server.Requests()) != 3 {
		t.Fatalf("expected exactly two repair calls, got %d total calls", len(server.Requests()))
	}
}

func TestRunnerStructuredRepairCallsExposeNoTools(t *testing.T) {
	registry := tools.NewRegistry()
	executions := 0
	if err := registry.Register(&countingTool{executions: &executions}); err != nil {
		t.Fatal(err)
	}

	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, registry)
	task := repairTestTask(Budget{
		MaxTurns:           1,
		FinalizeTurns:      1,
		MaxSemanticRepairs: 1,
	})
	task.ToolNames = []string{"repository_test_tool"}
	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 2 {
		t.Fatalf("expected one normal and one repair call, got %d", len(requests))
	}
	assertStructuredRequest(t, requests[1])
}

func TestRunnerFallsBackOnlyWhenStructuredOutputIsExplicitlyUnsupported(t *testing.T) {
	requests := make([]llm.ChatRequest, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request llm.ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests = append(requests, request)
		w.Header().Set("Content-Type", "application/json")
		if len(requests) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"response_format json_schema is not supported","type":"invalid_request_error","code":"unsupported_response_format"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(llm.ChatResponse{
			Choices: []llm.Choice{{Message: submissionMessage("call_legacy", validSubmissionArguments)}},
		})
	}))
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	result, err := runner.Run(context.Background(), repairTestTask(Budget{
		MaxTurns:      1,
		FinalizeTurns: 1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Findings) != `{"ok":true}` {
		t.Fatalf("unexpected fallback result: %s", result.Findings)
	}
	if len(requests) != 2 {
		t.Fatalf("expected structured request and legacy fallback, got %d", len(requests))
	}
	assertStructuredRequest(t, requests[0])
	assertOnlySubmitTool(t, requests[1])
	assertForcedSubmitToolChoice(t, requests[1].ToolChoice)
	if requests[1].ResponseFormat != nil {
		t.Fatalf("legacy fallback retained response_format: %#v", requests[1].ResponseFormat)
	}
	if !strings.Contains(
		strings.Join(logs, "\n"),
		"structured output unsupported; using legacy submit fallback",
	) {
		t.Fatalf("fallback was not logged: %v", logs)
	}
}

func TestRunnerSemanticFailureDoesNotTriggerLegacyFallback(t *testing.T) {
	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		submissionMessage("call_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, tools.NewRegistry())
	logs := make([]string, 0)
	runner.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if _, err := runner.Run(context.Background(), repairTestTask(Budget{
		MaxTurns:           1,
		FinalizeTurns:      1,
		MaxSemanticRepairs: 1,
	})); err != nil {
		t.Fatal(err)
	}

	requests := server.Requests()
	if len(requests) != 2 {
		t.Fatalf("expected structured finalization and repair, got %d", len(requests))
	}
	assertStructuredRequest(t, requests[0])
	assertStructuredRequest(t, requests[1])
	if strings.Contains(strings.Join(logs, "\n"), "legacy submit fallback") {
		t.Fatalf("semantic validation incorrectly triggered fallback: %v", logs)
	}
}

func TestRunnerDoesNotExecuteRepositoryToolsDuringRepair(t *testing.T) {
	registry := tools.NewRegistry()
	executions := 0
	if err := registry.Register(&countingTool{executions: &executions}); err != nil {
		t.Fatal(err)
	}

	server := newScriptedLLMServer(t, []llm.Message{
		submissionMessage("call_bad", invalidSubmissionArguments),
		{
			Role: "assistant",
			ToolCalls: []llm.ToolCall{
				{
					ID:   "call_repository",
					Type: "function",
					Function: llm.FunctionCall{
						Name:      "repository_test_tool",
						Arguments: `{}`,
					},
				},
			},
		},
		submissionMessage("call_format_repair", validSubmissionArguments),
	})
	defer server.Close()

	runner := testRunner(t, server.URL, registry)
	task := repairTestTask(Budget{
		MaxTurns:           1,
		FinalizeTurns:      1,
		MaxSemanticRepairs: 1,
	})
	task.ToolNames = []string{"repository_test_tool"}
	if _, err := runner.Run(context.Background(), task); err != nil {
		t.Fatalf("expected format repair after unavailable tool, got %v", err)
	}
	if executions != 0 {
		t.Fatalf("repository tool executed %d times during repair", executions)
	}
}

const validSubmissionArguments = `{"status":"completed","summary":"done","findings":{"ok":true}}`
const invalidSubmissionArguments = `{"status":"completed","summary":"done","findings":{}}`

type scriptedLLMServer struct {
	*httptest.Server

	mu       sync.Mutex
	messages []llm.Message
	requests []llm.ChatRequest
}

func newScriptedLLMServer(
	t *testing.T,
	messages []llm.Message,
) *scriptedLLMServer {
	t.Helper()

	scripted := &scriptedLLMServer{messages: messages}
	scripted.Server = httptest.NewServer(http.HandlerFunc(scripted.serveHTTP))

	return scripted
}

func (s *scriptedLLMServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	var request llm.ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	index := len(s.requests)
	s.requests = append(s.requests, request)
	if index >= len(s.messages) {
		http.Error(w, "unexpected model call", http.StatusInternalServerError)
		return
	}

	message := s.messages[index]
	// Most older runner fixtures describe the final result as legacy submit-tool
	// arguments. For a structured-output request, return the same envelope as
	// assistant content so the fixture exercises the preferred path.
	if request.ResponseFormat != nil &&
		message.Content == "" &&
		len(message.ToolCalls) == 1 &&
		message.ToolCalls[0].Function.Name == submitToolName {
		message.Content = message.ToolCalls[0].Function.Arguments
		message.ToolCalls = nil
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(llm.ChatResponse{
		Choices: []llm.Choice{{Message: message}},
	})
}

func (s *scriptedLLMServer) Requests() []llm.ChatRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]llm.ChatRequest(nil), s.requests...)
}

func submissionMessage(id, arguments string) llm.Message {
	return llm.Message{
		Role: "assistant",
		ToolCalls: []llm.ToolCall{
			{
				ID:   id,
				Type: "function",
				Function: llm.FunctionCall{
					Name:      submitToolName,
					Arguments: arguments,
				},
			},
		},
	}
}

func repairTestTask(budget Budget) Task {
	return Task{
		ID:           "repair-test",
		Objective:    "Test result repair behavior.",
		SubmitSchema: json.RawMessage(`{"type":"object"}`),
		ValidateResult: func(
			result *Result,
			evidence EvidenceLookup,
		) error {
			if string(result.Findings) != `{"ok":true}` {
				return errors.New("findings are invalid")
			}
			return nil
		},
		Budget: budget,
	}
}

func testRunner(
	t *testing.T,
	baseURL string,
	registry *tools.Registry,
) *Runner {
	t.Helper()
	return NewRunner(
		llm.NewClient(baseURL, "", "test-model"),
		registry,
		evidence.NewStore(t.TempDir()),
	)
}

func assertOnlySubmitTool(t *testing.T, request llm.ChatRequest) {
	t.Helper()
	if len(request.Tools) != 1 {
		t.Fatalf("expected only submit tool, got %d tools", len(request.Tools))
	}
	if request.Tools[0].Function.Name != submitToolName {
		t.Fatalf(
			"expected only %s, got %s",
			submitToolName,
			request.Tools[0].Function.Name,
		)
	}
}

func assertStructuredRequest(t *testing.T, request llm.ChatRequest) {
	t.Helper()
	if len(request.Tools) != 0 {
		t.Fatalf("structured request exposed %d tools", len(request.Tools))
	}
	if request.ToolChoice != nil {
		t.Fatalf("structured request sent tool_choice: %#v", request.ToolChoice)
	}
	if request.ResponseFormat == nil || request.ResponseFormat.Type != "json_schema" {
		t.Fatalf("structured request omitted JSON Schema response format: %#v", request.ResponseFormat)
	}
	if JSONValueKind(request.ResponseFormat.JSONSchema.Schema) != "object" {
		t.Fatalf("structured schema was not an object: %s", request.ResponseFormat.JSONSchema.Schema)
	}
}

func assertForcedSubmitToolChoice(t *testing.T, choice any) {
	t.Helper()
	object, ok := choice.(map[string]any)
	if !ok {
		t.Fatalf("forced tool choice was not an object: %#v", choice)
	}
	if object["type"] != "function" {
		t.Fatalf("forced tool choice type was %#v", object["type"])
	}
	function, ok := object["function"].(map[string]any)
	if !ok || function["name"] != submitToolName {
		t.Fatalf("forced tool choice function was %#v", object["function"])
	}
}

func requestContains(request llm.ChatRequest, text string) bool {
	for _, message := range request.Messages {
		if strings.Contains(message.Content, text) {
			return true
		}
	}
	return false
}

type countingTool struct {
	executions *int
}

func (t *countingTool) Name() string {
	return "repository_test_tool"
}

func (t *countingTool) Description() string {
	return "test repository tool"
}

func (t *countingTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}

func (t *countingTool) Execute(
	ctx context.Context,
	arguments json.RawMessage,
) (tools.Result, error) {
	*t.executions++
	return tools.Result{Content: json.RawMessage(`{"ok":true}`)}, nil
}
