package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/tools"
)

const submitToolName = "submit_investigation_result"

type Runner struct {
	LLM      *llm.Client
	Tools    *tools.Registry
	Evidence *evidence.Store

	Logf func(format string, args ...any)
}

func NewRunner(
	client *llm.Client,
	registry *tools.Registry,
	evidenceStore *evidence.Store,
) *Runner {
	return &Runner{
		LLM:      client,
		Tools:    registry,
		Evidence: evidenceStore,
	}
}

func (r *Runner) Run(
	ctx context.Context,
	task Task,
) (*Result, error) {
	budget := task.Budget

	if budget.MaxTurns == 0 {
		budget.MaxTurns = 25
	}

	if budget.MaxToolCalls == 0 {
		budget.MaxToolCalls = 100
	}

	if budget.MaxResultRepairs == 0 {
		budget.MaxResultRepairs = 2
	}

	if budget.MaxDuration == 0 {
		budget.MaxDuration = 10 * time.Minute
	}

	ctx, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()

	definitions := llm.ToolDefinitions(
		r.Tools,
		task.ToolNames,
	)

	definitions = append(definitions, llm.ToolDefinition{
		Type: "function",
		Function: llm.FunctionDefinition{
			Name:        submitToolName,
			Description: "Submit the final structured result for this investigation. Call this when the investigation is complete.",
			Parameters:  task.SubmitSchema,
		},
	})

	systemPrompt := `You are a Noescope repository investigation sub-agent.

Your task is narrow and bounded. Investigate the requested objective using only the tools provided.

Rules:
- Investigate before making conclusions.
- Do not invent source files, symbols, routes, technologies, or evidence.
- Evidence IDs are created by Noescope and returned with tool results.
- Reference those evidence IDs when making significant claims.
- If something cannot be determined confidently, report it under unresolved.
- You have read-only repository access.
- Do not describe unrelated application functionality.
- When finished, you MUST call submit_investigation_result.
- Do not finish with a normal prose response.`

	if task.Instructions != "" {
		systemPrompt += "\n\nAdditional instructions:\n" + task.Instructions
	}

	messages := []llm.Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: task.Objective,
		},
	}

	toolCalls := 0
	repairs := 0

	for turn := 1; turn <= budget.MaxTurns; turn++ {
		if r.Logf != nil {
			r.Logf("[%s] model turn %d", task.ID, turn)
		}

		response, err := r.LLM.Chat(
			ctx,
			messages,
			definitions,
		)
		if err != nil {
			return nil, err
		}

		message := response.Choices[0].Message
		messages = append(messages, message)

		if len(message.ToolCalls) == 0 {
			repairs++

			if repairs > budget.MaxResultRepairs {
				return nil, fmt.Errorf(
					"task %s ended without submitting a result",
					task.ID,
				)
			}

			messages = append(messages, llm.Message{
				Role:    "user",
				Content: "You must continue the investigation or call submit_investigation_result with the final structured result.",
			})

			continue
		}

		for _, call := range message.ToolCalls {
			toolCalls++

			if toolCalls > budget.MaxToolCalls {
				return nil, fmt.Errorf(
					"task %s exceeded maximum tool calls",
					task.ID,
				)
			}

			if r.Logf != nil {
				r.Logf(
					"[%s] tool %s",
					task.ID,
					call.Function.Name,
				)
			}

			if call.Function.Name == submitToolName {
				var result Result

				if err := json.Unmarshal(
					[]byte(call.Function.Arguments),
					&result,
				); err != nil {
					repairs++

					if repairs > budget.MaxResultRepairs {
						return nil, fmt.Errorf(
							"invalid submitted result: %w",
							err,
						)
					}

					messages = append(messages, llm.Message{
						Role:       "tool",
						ToolCallID: call.ID,
						Content: fmt.Sprintf(
							`{"error":"invalid result JSON: %s"}`,
							err.Error(),
						),
					})

					continue
				}

				if result.Status == "" ||
					result.Summary == "" ||
					len(result.Findings) == 0 {
					repairs++

					if repairs > budget.MaxResultRepairs {
						return nil, fmt.Errorf(
							"task %s exceeded result repair limit",
							task.ID,
						)
					}

					messages = append(messages, llm.Message{
						Role:       "tool",
						ToolCallID: call.ID,
						Content:    `{"error":"status, summary, and findings are required"}`,
					})

					continue
				}

				// Validate common claim fields and evidence references.
				submissionErr := validateClaims(
					result.Claims,
					r.Evidence,
				)

				if submissionErr == nil && task.ValidateResult != nil {
					submissionErr = task.ValidateResult(
						&result,
						r.Evidence,
					)
				}

				if submissionErr != nil {
					repairs++

					if repairs > budget.MaxResultRepairs {
						return nil, fmt.Errorf(
							"task %s exceeded result repair limit: %w",
							task.ID,
							submissionErr,
						)
					}

					errorPayload, _ := json.Marshal(map[string]any{
						"error":       submissionErr.Error(),
						"instruction": "Correct the submitted result using only valid evidence IDs, then call submit_investigation_result again.",
					})

					messages = append(messages, llm.Message{
						Role:       "tool",
						ToolCallID: call.ID,
						Content:    string(errorPayload),
					})

					continue
				}

				return &result, nil
			}

			rawArgs := json.RawMessage(call.Function.Arguments)

			toolResult, toolErr := r.Tools.Execute(
				ctx,
				call.Function.Name,
				rawArgs,
			)

			if toolErr != nil {
				errorPayload, _ := json.Marshal(map[string]any{
					"error": toolErr.Error(),
				})

				messages = append(messages, llm.Message{
					Role:       "tool",
					ToolCallID: call.ID,
					Content:    string(errorPayload),
				})

				continue
			}

			records, err := r.Evidence.AddDrafts(
				task.ID,
				toolResult.Evidence,
			)
			if err != nil {
				return nil, err
			}

			evidenceIDs := make(
				[]string,
				0,
				len(records),
			)

			for _, record := range records {
				evidenceIDs = append(
					evidenceIDs,
					record.ID,
				)
			}

			payload := struct {
				Result      json.RawMessage `json:"result"`
				EvidenceIDs []string        `json:"evidence_ids,omitempty"`
			}{
				Result:      toolResult.Content,
				EvidenceIDs: evidenceIDs,
			}

			data, err := json.Marshal(payload)
			if err != nil {
				return nil, err
			}

			messages = append(messages, llm.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Content:    string(data),
			})
		}
	}

	return nil, fmt.Errorf(
		"task %s exceeded maximum model turns",
		task.ID,
	)
}

func validateClaims(
	claims []Claim,
	evidence EvidenceLookup,
) error {
	for i, claim := range claims {
		if claim.Confidence < 0 || claim.Confidence > 1 {
			return fmt.Errorf(
				"claim[%d] has invalid confidence %.2f",
				i,
				claim.Confidence,
			)
		}

		if claim.Confidence > 0 &&
			len(claim.EvidenceIDs) == 0 {
			return fmt.Errorf(
				"claim[%d] %q has confidence %.2f but no evidence",
				i,
				claim.Statement,
				claim.Confidence,
			)
		}

		for _, evidenceID := range claim.EvidenceIDs {
			if !evidence.Exists(evidenceID) {
				return fmt.Errorf(
					"claim[%d] references unknown evidence ID %q",
					i,
					evidenceID,
				)
			}
		}
	}

	return nil
}
