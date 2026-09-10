package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStructuredChatSerializesSchemaAsObjectWithoutTools(t *testing.T) {
	var rawRequest map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&rawRequest); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"status\":\"completed\",\"summary\":\"done\",\"findings\":{}}"}}]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "test-model")
	_, err := client.StructuredChat(
		context.Background(),
		[]Message{{Role: "user", Content: "finalize"}},
		"investigation_result",
		json.RawMessage(`{"type":"object","properties":{"findings":{"type":"object"}}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rawRequest["tools"]; ok {
		t.Fatal("structured request serialized tools")
	}
	if _, ok := rawRequest["tool_choice"]; ok {
		t.Fatal("structured request serialized tool_choice")
	}

	var responseFormat struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	}
	if err := json.Unmarshal(rawRequest["response_format"], &responseFormat); err != nil {
		t.Fatal(err)
	}
	if responseFormat.Type != "json_schema" || responseFormat.JSONSchema.Name != "investigation_result" {
		t.Fatalf("unexpected response format: %#v", responseFormat)
	}
	if len(responseFormat.JSONSchema.Schema) == 0 || responseFormat.JSONSchema.Schema[0] != '{' {
		t.Fatalf("schema was not serialized as an object: %s", responseFormat.JSONSchema.Schema)
	}
	var schema struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(responseFormat.JSONSchema.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["findings"].Type != "object" {
		t.Fatalf("nested findings type was %q", schema.Properties["findings"].Type)
	}
}

func TestIsResponseFormatUnsupported(t *testing.T) {
	for _, unsupported := range []*RequestError{
		{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Message:    "response_format json_schema is not supported",
		},
		{
			StatusCode: http.StatusUnprocessableEntity,
			Status:     "422 Unprocessable Entity",
			Message:    "Extra inputs are not permitted: response_format",
		},
	} {
		if !IsResponseFormatUnsupported(unsupported) {
			t.Fatalf("explicit unsupported response_format error was not recognized: %v", unsupported)
		}
	}
	for _, err := range []error{
		&RequestError{StatusCode: http.StatusBadRequest, Message: "invalid evidence ID"},
		&RequestError{StatusCode: http.StatusInternalServerError, Message: "json_schema is not supported"},
		errors.New("response_format json_schema is not supported"),
	} {
		if IsResponseFormatUnsupported(err) {
			t.Fatalf("unrelated error triggered fallback: %v", err)
		}
	}
}

func TestChat(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/completions" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}

			var request ChatRequest

			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}

			if request.Model != "test-model" {
				t.Fatalf(
					"expected model test-model, got %q",
					request.Model,
				)
			}

			w.Header().Set("Content-Type", "application/json")

			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-test",
				"choices": [
					{
						"index": 0,
						"message": {
							"role": "assistant",
							"content": "hello"
						},
						"finish_reason": "stop"
					}
				],
				"usage": {
					"prompt_tokens": 10,
					"completion_tokens": 2,
					"total_tokens": 12
				}
			}`))
		}),
	)
	defer server.Close()

	client := NewClient(
		server.URL+"/v1",
		"",
		"test-model",
	)

	response, err := client.Chat(
		context.Background(),
		[]Message{
			{
				Role:    "user",
				Content: "hello",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if response.Choices[0].Message.Content != "hello" {
		t.Fatalf(
			"unexpected response: %q",
			response.Choices[0].Message.Content,
		)
	}
}

func TestToolCallResponse(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-tool-test",
				"choices": [
					{
						"index": 0,
						"message": {
							"role": "assistant",
							"tool_calls": [
								{
									"id": "call_123",
									"type": "function",
									"function": {
										"name": "search",
										"arguments": "{\"query\":\"auth\"}"
									}
								}
							]
						},
						"finish_reason": "tool_calls"
					}
				]
			}`))
		}),
	)
	defer server.Close()

	client := NewClient(
		server.URL+"/v1",
		"",
		"test-model",
	)

	response, err := client.Chat(
		context.Background(),
		[]Message{
			{
				Role:    "user",
				Content: "find authentication code",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	calls := response.Choices[0].Message.ToolCalls

	if len(calls) != 1 {
		t.Fatalf(
			"expected 1 tool call, got %d",
			len(calls),
		)
	}

	if calls[0].Function.Name != "search" {
		t.Fatalf(
			"expected search tool, got %q",
			calls[0].Function.Name,
		)
	}
}
