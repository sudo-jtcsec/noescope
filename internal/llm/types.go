package llm

import "encoding/json"

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolDefinition struct {
	Type     string             `json:"type"`
	Function FunctionDefinition `json:"function"`
}

type FunctionDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type ChatRequest struct {
	Model          string           `json:"model"`
	Messages       []Message        `json:"messages"`
	Tools          []ToolDefinition `json:"tools,omitempty"`
	ToolChoice     interface{}      `json:"tool_choice,omitempty"`
	ResponseFormat *ResponseFormat  `json:"response_format,omitempty"`
	Temperature    float64          `json:"temperature"`
}

type ResponseFormat struct {
	Type       string             `json:"type"`
	JSONSchema JSONSchemaResponse `json:"json_schema"`
}

type JSONSchemaResponse struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
}

type ToolChoice struct {
	Type     string             `json:"type"`
	Function ToolChoiceFunction `json:"function"`
}

type ToolChoiceFunction struct {
	Name string `json:"name"`
}

func ForceTool(name string) ToolChoice {
	return ToolChoice{
		Type: "function",
		Function: ToolChoiceFunction{
			Name: name,
		},
	}
}

type ChatResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int  `json:"prompt_tokens"`
	CompletionTokens *int `json:"completion_tokens,omitempty"`
	TotalTokens      int  `json:"total_tokens"`
}

type APIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}
