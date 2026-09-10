package investigation

import (
	"encoding/json"

	"github.com/sudo-jtcsec/noescope/internal/llm"
)

// Keep the message history itself well below the model context window.
// Tool definitions, system prompts, and model output also consume context,
// so this is intentionally conservative for a 32K-token model.
const contextMessageByteBudget = 45000

// prepareMessages returns a copy of the conversation suitable for sending
// to the LLM.
//
// The complete conversation remains in memory inside the Runner. Only the
// request sent to the model is compacted.
//
// Old tool messages retain their ToolCallID so OpenAI-compatible APIs still
// see a valid assistant-tool-call -> tool-response sequence.
func prepareMessages(
	messages []llm.Message,
	maxBytes int,
) ([]llm.Message, bool, int, int) {
	out := append([]llm.Message(nil), messages...)

	before := estimateMessageBytes(out)

	if before <= maxBytes {
		return out, false, before, before
	}

	// Preserve system and objective messages.
	//
	// Prefer to keep the four newest messages in full because they contain
	// the investigation's most recent observations.
	protectedRecent := 4
	cutoff := len(out) - protectedRecent

	if cutoff < 2 {
		cutoff = 2
	}

	// First pass: compact only older tool outputs.
	for i := 2; i < cutoff; i++ {
		if estimateMessageBytes(out) <= maxBytes {
			break
		}

		if out[i].Role != "tool" {
			continue
		}

		out[i].Content = compactToolContent(out[i].Content)
	}

	// Second pass: if still too large, compact tool outputs closer to the
	// present, oldest first.
	for i := 2; i < len(out); i++ {
		if estimateMessageBytes(out) <= maxBytes {
			break
		}

		if out[i].Role != "tool" {
			continue
		}

		out[i].Content = compactToolContent(out[i].Content)
	}

	// Assistant messages normally contain tool calls rather than large prose,
	// but compact old prose as a final safeguard. ToolCalls are preserved.
	for i := 2; i < cutoff; i++ {
		if estimateMessageBytes(out) <= maxBytes {
			break
		}

		if out[i].Role != "assistant" || len(out[i].Content) <= 500 {
			continue
		}

		out[i].Content = "[Earlier assistant reasoning compacted by Noescope.]"
	}

	after := estimateMessageBytes(out)

	return out, true, before, after
}

func estimateMessageBytes(messages []llm.Message) int {
	data, err := json.Marshal(messages)
	if err != nil {
		return 0
	}

	return len(data)
}

func compactToolContent(content string) string {
	// Tool responses currently use:
	//
	// {
	//   "result": ...,
	//   "evidence_ids": [...]
	// }
	//
	// Preserve the evidence IDs so the model can still use evidence gathered
	// earlier in the investigation even though the bulky source content is
	// no longer in active context.
	var envelope struct {
		EvidenceIDs []string `json:"evidence_ids"`
	}

	_ = json.Unmarshal([]byte(content), &envelope)

	payload := map[string]any{
		"compacted":      true,
		"original_bytes": len(content),
		"note":           "Earlier tool output omitted from active context. The evidence remains persisted by Noescope.",
	}

	if len(envelope.EvidenceIDs) > 0 {
		payload["evidence_ids"] = envelope.EvidenceIDs
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return `{"compacted":true}`
	}

	return string(data)
}
