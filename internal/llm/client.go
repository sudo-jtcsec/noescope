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
	if c.BaseURL == "" {
		return nil, fmt.Errorf("LLM base URL is required")
	}

	if c.Model == "" {
		return nil, fmt.Errorf("LLM model is required")
	}

	requestBody := ChatRequest{
		Model:       c.Model,
		Messages:    messages,
		Tools:       tools,
		Temperature: 0.1,
	}

	if len(tools) > 0 {
		requestBody.ToolChoice = "auto"
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
			return nil, fmt.Errorf(
				"LLM API returned %s: %s",
				resp.Status,
				apiErr.Error.Message,
			)
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
