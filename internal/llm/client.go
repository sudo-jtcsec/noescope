package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	Model   string

	httpClient *http.Client
}

func NewClient(baseURL, apiKey, model string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,

		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (c *Client) Chat(
	ctx context.Context,
	messages []Message,
	tools []ToolDefinition,
) (*ChatResponse, error) {
	var toolChoice any
	if len(tools) > 0 {
		toolChoice = "auto"
	}

	return c.chat(ctx, messages, tools, toolChoice, nil)
}

func (c *Client) ChatWithToolChoice(
	ctx context.Context,
	messages []Message,
	tools []ToolDefinition,
	toolChoice ToolChoice,
) (*ChatResponse, error) {
	return c.chat(ctx, messages, tools, toolChoice, nil)
}

func (c *Client) StructuredChat(
	ctx context.Context,
	messages []Message,
	schemaName string,
	schema json.RawMessage,
) (*ChatResponse, error) {
	return c.chat(
		ctx,
		messages,
		nil,
		nil,
		&ResponseFormat{
			Type: "json_schema",
			JSONSchema: JSONSchemaResponse{
				Name:   schemaName,
				Schema: schema,
			},
		},
	)
}

func (c *Client) chat(
	ctx context.Context,
	messages []Message,
	tools []ToolDefinition,
	toolChoice any,
	responseFormat *ResponseFormat,
) (*ChatResponse, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("LLM base URL is required")
	}

	if c.Model == "" {
		return nil, fmt.Errorf("LLM model is required")
	}

	requestBody := ChatRequest{
		Model:          c.Model,
		Messages:       messages,
		Tools:          tools,
		ToolChoice:     toolChoice,
		ResponseFormat: responseFormat,
		Temperature:    0.1,
	}

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal LLM request: %w", err)
	}

	endpoint := c.BaseURL + "/chat/completions"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("create LLM request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read LLM response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIErrorResponse

		if err := json.Unmarshal(body, &apiErr); err == nil &&
			apiErr.Error.Message != "" {
			return nil, &RequestError{
				StatusCode: resp.StatusCode,
				Status:     resp.Status,
				Message:    apiErr.Error.Message,
				Type:       apiErr.Error.Type,
				Code:       fmt.Sprint(apiErr.Error.Code),
			}
		}

		return nil, fmt.Errorf(
			"LLM API returned %s: %s",
			resp.Status,
			string(body),
		)
	}

	var result ChatResponse

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf(
			"parse LLM response: %w",
			err,
		)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("LLM returned no choices")
	}

	return &result, nil
}
