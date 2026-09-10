package investigation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sudo-jtcsec/noescope/internal/llm"
)

// Keep the message history itself well below the model context window.
// Tool definitions, system prompts, and model output also consume context,
// so this is intentionally conservative for a 32K-token model.
const contextMessageByteBudget = 45000

var ErrContextCannotCompact = errors.New(
	"context cannot be compacted below byte budget",
)

type messagePreparationOptions struct {
	compactSubmitArguments bool
	recentGroupsToKeep     int
}

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
) ([]llm.Message, bool, int, int, error) {
	return prepareMessagesWithOptions(
		messages,
		maxBytes,
		messagePreparationOptions{recentGroupsToKeep: 4},
	)
}

func prepareRepairMessages(
	messages []llm.Message,
	maxBytes int,
) ([]llm.Message, bool, int, int, error) {
	return prepareMessagesWithOptions(
		messages,
		maxBytes,
		messagePreparationOptions{
			compactSubmitArguments: true,
			recentGroupsToKeep:     2,
		},
	)
}

func prepareMessagesWithOptions(
	messages []llm.Message,
	maxBytes int,
	options messagePreparationOptions,
) ([]llm.Message, bool, int, int, error) {
	out := cloneMessages(messages)

	before := estimateMessageBytes(out)
	compacted := false

	submitCallIDs := make(map[string]bool)
	if options.compactSubmitArguments {
		for i := range out {
			if out[i].Role != "assistant" {
				continue
			}
			for j := range out[i].ToolCalls {
				call := &out[i].ToolCalls[j]
				if call.Function.Name != submitToolName {
					continue
				}
				submitCallIDs[call.ID] = true
				if call.Function.Arguments != "{}" {
					call.Function.Arguments = "{}"
					compacted = true
				}
			}
		}
	}

	if estimateMessageBytes(out) <= maxBytes {
		after := estimateMessageBytes(out)
		return out, compacted, before, after, nil
	}

	// Preserve system and objective messages.
	//
	// Prefer to keep the four newest messages in full because they contain
	// the investigation's most recent observations.
	protectedRecent := options.recentGroupsToKeep
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

		if submitCallIDs[out[i].ToolCallID] {
			continue
		}

		compactedContent := compactToolContent(out[i].Content)
		if len(compactedContent) < len(out[i].Content) {
			out[i].Content = compactedContent
			compacted = true
		}
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

		if submitCallIDs[out[i].ToolCallID] {
			continue
		}

		compactedContent := compactToolContent(out[i].Content)
		if len(compactedContent) < len(out[i].Content) {
			out[i].Content = compactedContent
			compacted = true
		}
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
		compacted = true
	}

	// If protected recent prose alone is still too large, compact it too.
	// System instructions and the task objective remain untouched.
	for i := 2; i < len(out); i++ {
		if estimateMessageBytes(out) <= maxBytes {
			break
		}
		if out[i].Role != "assistant" || len(out[i].Content) <= 500 {
			continue
		}
		out[i].Content = "[Earlier assistant reasoning compacted by Noescope.]"
		compacted = true
	}

	// Repair prompts only need a bounded recent slice of the exploration.
	// Drop the oldest complete groups as a final measure, never separating an
	// assistant tool call from its tool responses.
	for estimateMessageBytes(out) > maxBytes {
		groups := completeMessageGroups(out, 2)
		if len(groups) <= options.recentGroupsToKeep {
			break
		}

		dropBefore := len(groups) - options.recentGroupsToKeep
		dropped := false
		for _, group := range groups[:dropBefore] {
			if !group.complete {
				continue
			}
			out = append(out[:group.start], out[group.end:]...)
			compacted = true
			dropped = true
			break
		}
		if !dropped {
			break
		}
	}

	after := estimateMessageBytes(out)
	if after > maxBytes {
		return nil, compacted, before, after, fmt.Errorf(
			"%w: %d bytes exceeds %d-byte budget",
			ErrContextCannotCompact,
			after,
			maxBytes,
		)
	}

	return out, compacted, before, after, nil
}

type messageGroup struct {
	start    int
	end      int
	complete bool
}

func completeMessageGroups(
	messages []llm.Message,
	start int,
) []messageGroup {
	groups := make([]messageGroup, 0, len(messages)-start)
	for i := start; i < len(messages); {
		message := messages[i]
		if message.Role != "assistant" || len(message.ToolCalls) == 0 {
			groups = append(groups, messageGroup{
				start:    i,
				end:      i + 1,
				complete: message.Role != "tool",
			})
			i++
			continue
		}

		expected := make(map[string]bool, len(message.ToolCalls))
		for _, call := range message.ToolCalls {
			expected[call.ID] = true
		}
		end := i + 1
		for end < len(messages) && messages[end].Role == "tool" {
			delete(expected, messages[end].ToolCallID)
			end++
		}
		groups = append(groups, messageGroup{
			start:    i,
			end:      end,
			complete: len(expected) == 0,
		})
		i = end
	}

	return groups
}

func cloneMessages(messages []llm.Message) []llm.Message {
	out := make([]llm.Message, len(messages))
	copy(out, messages)
	for i := range out {
		if len(messages[i].ToolCalls) == 0 {
			continue
		}
		out[i].ToolCalls = append(
			[]llm.ToolCall(nil),
			messages[i].ToolCalls...,
		)
	}
	return out
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
