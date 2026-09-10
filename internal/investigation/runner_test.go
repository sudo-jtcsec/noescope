package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
							Role: "assistant",
							ToolCalls: []llm.ToolCall{
								{
									ID:   "call_submit",
									Type: "function",
									Function: llm.FunctionCall{
										Name:      submitToolName,
										Arguments: `{"status":"completed","summary":"done","findings":{"authentication_present":false,"confidence":0,"evidence_ids":[],"mechanisms":[]}}`,
									},
								},
							},
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
			MaxTurns:      3,
			FinalizeTurns: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := <-requests
	if len(request.Messages) != 2 {
		t.Fatalf(
			"expected only the initial system and task messages, got %d",
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

func TestRunnerLogsRejectedResultAndRepairRequest(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(llm.ChatResponse{
				Choices: []llm.Choice{
					{
						Message: llm.Message{
							Role: "assistant",
							ToolCalls: []llm.ToolCall{
								{
									ID:   "call_submit",
									Type: "function",
									Function: llm.FunctionCall{
										Name:      submitToolName,
										Arguments: `{"status":"completed","summary":"done","findings":{}}`,
									},
								},
							},
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
			MaxTurns:         3,
			MaxResultRepairs: 2,
			FinalizeTurns:    1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	joinedLogs := strings.Join(logs, "\n")
	for _, expected := range []string{
		"[architecture] result rejected: important_directories[4] has confidence 0.80 but no evidence",
		"[architecture] requesting result repair",
	} {
		if !strings.Contains(joinedLogs, expected) {
			t.Fatalf("logs do not contain %q:\n%s", expected, joinedLogs)
		}
	}
}
