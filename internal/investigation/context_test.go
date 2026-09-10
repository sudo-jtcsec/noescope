package investigation

import (
	"encoding/json"
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

	got, compacted, before, after := prepareMessages(
		messages,
		10000,
	)

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

	got, compacted, before, after := prepareMessages(
		messages,
		5000,
	)

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
