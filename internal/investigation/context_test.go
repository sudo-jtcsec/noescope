package investigation

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/llm"
)

func TestPrepareMessagesDoesNotCompactSmallContext(t *testing.T) {
	messages := []llm.Message{
		{
			Role:    "system",
			Content: "system",
		},
		{
			Role:    "user",
			Content: "objective",
		},
		{
			Role:    "assistant",
			Content: "hello",
		},
	}

	got, compacted, before, after, err := prepareMessages(
		messages,
		10000,
	)
	if err != nil {
		t.Fatal(err)
	}

	if compacted {
		t.Fatal("small context should not have been compacted")
	}

	if before != after {
		t.Fatalf(
			"expected unchanged size, before=%d after=%d",
			before,
			after,
		)
	}

	if len(got) != len(messages) {
		t.Fatal("message count changed")
	}
}

func TestPrepareMessagesCompactsOldToolResults(t *testing.T) {
	large := strings.Repeat("source code line\n", 5000)
	toolContent, err := json.Marshal(map[string]any{
		"result":       large,
		"evidence_ids": []string{"ev_test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	messages := []llm.Message{
		{
			Role:    "system",
			Content: "system",
		},
		{
			Role:    "user",
			Content: "objective",
		},
		{
			Role: "assistant",
			ToolCalls: []llm.ToolCall{
				{
					ID:   "call_1",
					Type: "function",
					Function: llm.FunctionCall{
						Name:      "read_file",
						Arguments: `{"path":"main.go"}`,
					},
				},
			},
		},
		{
			Role:       "tool",
			ToolCallID: "call_1",
			Content:    string(toolContent),
		},
		{
			Role:    "assistant",
			Content: "recent reasoning",
		},
		{
			Role:    "user",
			Content: "continue",
		},
		{
			Role:    "assistant",
			Content: "recent assistant",
		},
		{
			Role:    "user",
			Content: "recent user",
		},
	}

	got, compacted, before, after, err := prepareMessages(
		messages,
		5000,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !compacted {
		t.Fatal("expected context compaction")
	}

	if after >= before {
		t.Fatalf(
			"expected smaller context, before=%d after=%d",
			before,
			after,
		)
	}

	if got[3].ToolCallID != "call_1" {
		t.Fatal("tool call ID was not preserved")
	}

	if !strings.Contains(got[3].Content, `"compacted":true`) {
		t.Fatal("tool content was not compacted")
	}

	if !strings.Contains(got[3].Content, "ev_test") {
		t.Fatal("evidence ID was not preserved")
	}
}

func TestPrepareRepairMessagesCompactsRejectedSubmissionArguments(t *testing.T) {
	rejectedArguments := `{"status":"completed","summary":"` +
		strings.Repeat("summary", 2000) +
		`","findings":{"payload":"` + strings.Repeat("x", 100000) + `"}}`
	validationError := `{"error":"status, summary, and findings are required"}`
	messages := []llm.Message{
		{Role: "system", Content: "system instructions"},
		{Role: "user", Content: "task objective"},
		{
			Role: "assistant",
			ToolCalls: []llm.ToolCall{{
				ID:   "call_read",
				Type: "function",
				Function: llm.FunctionCall{
					Name:      "read_file",
					Arguments: `{"path":"app.php"}`,
				},
			}},
		},
		{
			Role:       "tool",
			ToolCallID: "call_read",
			Content:    `{"result":"source","evidence_ids":["ev_source"]}`,
		},
		{
			Role: "assistant",
			ToolCalls: []llm.ToolCall{{
				ID:   "call_submit",
				Type: "function",
				Function: llm.FunctionCall{
					Name:      submitToolName,
					Arguments: rejectedArguments,
				},
			}},
		},
		{
			Role:       "tool",
			ToolCallID: "call_submit",
			Content:    validationError,
		},
	}

	got, compacted, before, after, err := prepareRepairMessages(
		messages,
		contextMessageByteBudget,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !compacted || after >= before {
		t.Fatalf("expected repair compaction, before=%d after=%d", before, after)
	}
	if after > contextMessageByteBudget {
		t.Fatalf("repair context exceeds budget: %d", after)
	}
	t.Logf("repair context compacted from %d to %d bytes", before, after)
	if strings.Contains(string(mustMarshalMessages(t, got)), strings.Repeat("x", 100)) {
		t.Fatal("rejected submission arguments remain in repair context")
	}
	if messages[4].ToolCalls[0].Function.Arguments != rejectedArguments {
		t.Fatal("canonical message history was mutated")
	}

	assertToolCallPaired(t, got, "call_submit", submitToolName)
	assertNoOrphanedToolResponses(t, got)
	if !containsToolResponse(got, "call_submit", validationError) {
		t.Fatal("validation error response was not preserved")
	}
}

func TestPrepareRepairMessagesCompactsMultipleRejectedSubmissions(t *testing.T) {
	messages := []llm.Message{
		{Role: "system", Content: "system"},
		{Role: "user", Content: "objective"},
	}
	for i := 1; i <= 2; i++ {
		id := "call_submit_" + string(rune('0'+i))
		messages = append(messages,
			llm.Message{
				Role: "assistant",
				ToolCalls: []llm.ToolCall{{
					ID:   id,
					Type: "function",
					Function: llm.FunctionCall{
						Name:      submitToolName,
						Arguments: `{"findings":"` + strings.Repeat("z", 100000) + `"}`,
					},
				}},
			},
			llm.Message{
				Role:       "tool",
				ToolCallID: id,
				Content:    `{"error":"validation failure ` + string(rune('0'+i)) + `"}`,
			},
		)
	}

	got, _, before, after, err := prepareRepairMessages(
		messages,
		contextMessageByteBudget,
	)
	if err != nil {
		t.Fatal(err)
	}
	if after > contextMessageByteBudget {
		t.Fatalf("repair context exceeds budget: %d", after)
	}
	t.Logf("multiple-repair context compacted from %d to %d bytes", before, after)
	for i := 1; i <= 2; i++ {
		id := "call_submit_" + string(rune('0'+i))
		assertToolCallPaired(t, got, id, submitToolName)
		if !containsToolResponse(
			got,
			id,
			`{"error":"validation failure `+string(rune('0'+i))+`"}`,
		) {
			t.Fatalf("validation response for %s was not preserved", id)
		}
	}
	assertNoOrphanedToolResponses(t, got)
}

func TestPrepareMessagesReturnsErrorWhenCeilingCannotBeMet(t *testing.T) {
	messages := []llm.Message{
		{Role: "system", Content: strings.Repeat("s", 2000)},
		{Role: "user", Content: "objective"},
	}

	_, _, _, after, err := prepareMessages(messages, 1000)
	if !errors.Is(err, ErrContextCannotCompact) {
		t.Fatalf("expected ErrContextCannotCompact, got %v", err)
	}
	if after <= 1000 {
		t.Fatalf("expected uncompacted context above ceiling, got %d", after)
	}
}

func mustMarshalMessages(t *testing.T, messages []llm.Message) []byte {
	t.Helper()
	data, err := json.Marshal(messages)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertToolCallPaired(
	t *testing.T,
	messages []llm.Message,
	callID string,
	name string,
) {
	t.Helper()
	callIndex := -1
	responseIndex := -1
	for i, message := range messages {
		for _, call := range message.ToolCalls {
			if call.ID == callID {
				callIndex = i
				if call.Function.Name != name {
					t.Fatalf("tool call %s name changed to %s", callID, call.Function.Name)
				}
				if call.Function.Arguments != "{}" {
					t.Fatalf("tool call %s arguments were not compacted", callID)
				}
			}
		}
		if message.Role == "tool" && message.ToolCallID == callID {
			responseIndex = i
		}
	}
	if callIndex < 0 || responseIndex != callIndex+1 {
		t.Fatalf(
			"tool call %s is not immediately paired: call=%d response=%d",
			callID,
			callIndex,
			responseIndex,
		)
	}
}

func containsToolResponse(
	messages []llm.Message,
	callID string,
	content string,
) bool {
	for _, message := range messages {
		if message.Role == "tool" &&
			message.ToolCallID == callID &&
			message.Content == content {
			return true
		}
	}
	return false
}

func assertNoOrphanedToolResponses(t *testing.T, messages []llm.Message) {
	t.Helper()
	callIDs := make(map[string]bool)
	for _, message := range messages {
		for _, call := range message.ToolCalls {
			callIDs[call.ID] = true
		}
	}
	for _, message := range messages {
		if message.Role == "tool" && !callIDs[message.ToolCallID] {
			t.Fatalf("orphaned tool response %s", message.ToolCallID)
		}
	}
}
