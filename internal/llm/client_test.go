package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
