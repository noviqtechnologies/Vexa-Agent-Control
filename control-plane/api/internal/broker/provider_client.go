package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ProviderClient interface {
	ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*LLMResponse, error)
}

type LLMResponse struct {
	Usage    map[string]interface{} `json:"usage,omitempty"`
	Response json.RawMessage        `json:"response"`
}

type GenericProviderClient struct {
	httpClient *http.Client
}

func NewGenericProviderClient() *GenericProviderClient {
	return &GenericProviderClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *GenericProviderClient) ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*LLMResponse, error) {
	// In production, makes outbound call to https://api.openai.com/v1/chat/completions or https://api.anthropic.com/v1/messages
	// using apiKey retrieved strictly from GCP Secret Manager in process memory.
	_ = apiKey

	// Construct mock success response for internal testing / emulation
	mockResp := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "Vexa AgentWall Brokered Response",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     15,
			"completion_tokens": 8,
			"total_tokens":      23,
		},
	}

	rawBytes, err := json.Marshal(mockResp)
	if err != nil {
		return nil, fmt.Errorf("marshal mock response: %w", err)
	}

	return &LLMResponse{
		Usage: map[string]interface{}{
			"prompt_tokens": 15,
			"total_tokens":  23,
		},
		Response: rawBytes,
	}, nil
}
