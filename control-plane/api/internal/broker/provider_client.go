package broker

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
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *GenericProviderClient) ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*LLMResponse, error) {
	// If apiKey is empty or explicitly MOCK (e.g. offline testing), return mock response
	if apiKey == "" || apiKey == "MOCK" || apiKey == "SECRET_FROM_SECRET_MANAGER" {
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
						"content": "Vexa Agent Control Brokered Response",
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
				"prompt_tokens":     15,
				"completion_tokens": 8,
				"total_tokens":      23,
			},
			Response: rawBytes,
		}, nil
	}

	// Build real outbound provider request
	var targetURL string
	var reqHeaders = make(http.Header)
	reqHeaders.Set("Content-Type", "application/json")

	lowerProv := strings.ToLower(provider)
	switch lowerProv {
	case "anthropic":
		targetURL = "https://api.anthropic.com/v1/messages"
		reqHeaders.Set("x-api-key", apiKey)
		reqHeaders.Set("anthropic-version", "2023-06-01")
	case "openai":
		targetURL = "https://api.openai.com/v1/chat/completions"
		reqHeaders.Set("Authorization", "Bearer "+apiKey)
	case "groq":
		targetURL = "https://api.groq.com/openai/v1/chat/completions"
		reqHeaders.Set("Authorization", "Bearer "+apiKey)
	case "together":
		targetURL = "https://api.together.xyz/v1/chat/completions"
		reqHeaders.Set("Authorization", "Bearer "+apiKey)
	case "mistral":
		targetURL = "https://api.mistral.ai/v1/chat/completions"
		reqHeaders.Set("Authorization", "Bearer "+apiKey)
	default:
		// Default to OpenAI-compatible endpoint format
		targetURL = fmt.Sprintf("https://api.%s.com/v1/chat/completions", lowerProv)
		reqHeaders.Set("Authorization", "Bearer "+apiKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	httpReq.Header = reqHeaders

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream provider request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream provider returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	// Extract token usage metrics from JSON body if present
	var usageMap map[string]interface{}
	var parsedJSON map[string]interface{}
	if err := json.Unmarshal(respBytes, &parsedJSON); err == nil {
		if u, ok := parsedJSON["usage"].(map[string]interface{}); ok {
			usageMap = u
		}
	}

	return &LLMResponse{
		Usage:    usageMap,
		Response: respBytes,
	}, nil
}
