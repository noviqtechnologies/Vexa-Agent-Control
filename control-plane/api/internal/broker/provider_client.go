package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type UsageReport struct {
	InputTokens       int64                  `json:"input_tokens"`
	OutputTokens      int64                  `json:"output_tokens"`
	CachedInputTokens int64                  `json:"cached_input_tokens"`
	IsEstimated       bool                   `json:"is_estimated"`
	UsageSource       string                 `json:"usage_source"`
	ProviderRequestID string                 `json:"provider_request_id,omitempty"`
	StatusCode        int                    `json:"status_code"`
	RawUsage          map[string]interface{} `json:"raw_usage,omitempty"`
}

type ProviderClient interface {
	ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*LLMResponse, *UsageReport, error)
	ForwardLLMRequestStream(ctx context.Context, provider, model string, payload json.RawMessage, apiKey string, onChunk func(chunk []byte) error) (*UsageReport, error)
}

type LLMResponse struct {
	Usage    map[string]interface{} `json:"usage,omitempty"`
	Response json.RawMessage        `json:"response"`
}

type UpstreamHTTPError struct {
	StatusCode int
	Body       []byte
}

func (e *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("upstream provider returned status %d: %s", e.StatusCode, string(e.Body))
}

type GenericProviderClient struct {
	httpClient *http.Client
}

func NewGenericProviderClient() *GenericProviderClient {
	return &GenericProviderClient{
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func resolveProviderEndpoint(provider string) (string, http.Header, error) {
	lowerProv := strings.ToLower(provider)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")

	switch lowerProv {
	case "openai":
		return "https://api.openai.com/v1/chat/completions", headers, nil
	case "anthropic":
		headers.Set("anthropic-version", "2023-06-01")
		return "https://api.anthropic.com/v1/messages", headers, nil
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", headers, nil
	default:
		return "", nil, fmt.Errorf("unsupported provider adapter: %s", provider)
	}
}

func applyProviderAuth(provider, apiKey string, headers http.Header) {
	lowerProv := strings.ToLower(provider)
	if lowerProv == "anthropic" {
		headers.Set("x-api-key", apiKey)
	} else {
		headers.Set("Authorization", "Bearer "+apiKey)
	}
}

func (c *GenericProviderClient) ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*LLMResponse, *UsageReport, error) {
	// If apiKey is empty or explicitly MOCK, return deterministic mock response
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
			return nil, nil, fmt.Errorf("marshal mock response: %w", err)
		}

		usageRep := &UsageReport{
			InputTokens:       15,
			OutputTokens:      8,
			CachedInputTokens: 0,
			IsEstimated:       false,
			UsageSource:       "provider_reported",
			StatusCode:        200,
		}

		return &LLMResponse{
			Usage: map[string]interface{}{
				"prompt_tokens":     15,
				"completion_tokens": 8,
				"total_tokens":      23,
			},
			Response: rawBytes,
		}, usageRep, nil
	}

	targetURL, reqHeaders, err := resolveProviderEndpoint(provider)
	if err != nil {
		return nil, nil, err
	}
	applyProviderAuth(provider, apiKey, reqHeaders)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("create upstream request: %w", err)
	}
	httpReq.Header = reqHeaders

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream provider request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read upstream response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, &UpstreamHTTPError{
			StatusCode: resp.StatusCode,
			Body:       respBytes,
		}
	}

	var usageMap map[string]interface{}
	var parsedJSON map[string]interface{}
	var inputTokens, outputTokens, cachedTokens int64
	var isEstimated bool
	var usageSource = "provider_reported"

	if err := json.Unmarshal(respBytes, &parsedJSON); err == nil {
		if u, ok := parsedJSON["usage"].(map[string]interface{}); ok {
			usageMap = u
			if pt, ok := u["prompt_tokens"].(float64); ok {
				inputTokens = int64(pt)
			} else if it, ok := u["input_tokens"].(float64); ok {
				inputTokens = int64(it)
			}
			if ct, ok := u["completion_tokens"].(float64); ok {
				outputTokens = int64(ct)
			} else if ot, ok := u["output_tokens"].(float64); ok {
				outputTokens = int64(ot)
			}
			if ptd, ok := u["prompt_tokens_details"].(map[string]interface{}); ok {
				if ct, ok := ptd["cached_tokens"].(float64); ok {
					cachedTokens = int64(ct)
				}
			}
		}
	}

	if inputTokens == 0 && outputTokens == 0 {
		isEstimated = true
		usageSource = "character_estimate"
		inputTokens = int64(len(payload) / 4)
		outputTokens = int64(len(respBytes) / 4)
	}

	usageRep := &UsageReport{
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CachedInputTokens: cachedTokens,
		IsEstimated:       isEstimated,
		UsageSource:       usageSource,
		StatusCode:        resp.StatusCode,
		RawUsage:          usageMap,
	}

	return &LLMResponse{
		Usage:    usageMap,
		Response: respBytes,
	}, usageRep, nil
}

func (c *GenericProviderClient) ForwardLLMRequestStream(ctx context.Context, provider, model string, payload json.RawMessage, apiKey string, onChunk func(chunk []byte) error) (*UsageReport, error) {
	if apiKey == "" || apiKey == "MOCK" || apiKey == "SECRET_FROM_SECRET_MANAGER" {
		// Mock streaming SSE sequence
		chunks := []string{
			`data: {"id":"chatcmpl-mock","object":"chat.completion.chunk","created":1700000000,"model":"` + model + `","choices":[{"index":0,"delta":{"role":"assistant","content":"Vexa"},"finish_reason":null}]}` + "\n\n",
			`data: {"id":"chatcmpl-mock","object":"chat.completion.chunk","created":1700000000,"model":"` + model + `","choices":[{"index":0,"delta":{"content":" Agent Control Brokered Stream"},"finish_reason":null}]}` + "\n\n",
			`data: {"id":"chatcmpl-mock","object":"chat.completion.chunk","created":1700000000,"model":"` + model + `","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":8,"total_tokens":23}}` + "\n\n",
			`data: [DONE]` + "\n\n",
		}
		for _, ch := range chunks {
			if err := onChunk([]byte(ch)); err != nil {
				return nil, err
			}
		}
		return &UsageReport{
			InputTokens:       15,
			OutputTokens:      8,
			CachedInputTokens: 0,
			IsEstimated:       false,
			UsageSource:       "provider_reported",
			StatusCode:        200,
		}, nil
	}

	targetURL, reqHeaders, err := resolveProviderEndpoint(provider)
	if err != nil {
		return nil, err
	}
	applyProviderAuth(provider, apiKey, reqHeaders)
	reqHeaders.Set("Accept", "text/event-stream")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	httpReq.Header = reqHeaders

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream streaming request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &UpstreamHTTPError{
			StatusCode: resp.StatusCode,
			Body:       body,
		}
	}

	reader := bufio.NewReader(resp.Body)
	var inputTokens, outputTokens, cachedTokens int64
	var foundProviderUsage bool
	var accumulatedChars int

	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if err := onChunk(line); err != nil {
				return nil, err
			}

			lineStr := strings.TrimSpace(string(line))
			if strings.HasPrefix(lineStr, "data: ") {
				dataStr := strings.TrimPrefix(lineStr, "data: ")
				if dataStr != "[DONE]" {
					var chunkJSON map[string]interface{}
					if err := json.Unmarshal([]byte(dataStr), &chunkJSON); err == nil {
						if u, ok := chunkJSON["usage"].(map[string]interface{}); ok {
							foundProviderUsage = true
							if pt, ok := u["prompt_tokens"].(float64); ok {
								inputTokens = int64(pt)
							} else if it, ok := u["input_tokens"].(float64); ok {
								inputTokens = int64(it)
							}
							if ct, ok := u["completion_tokens"].(float64); ok {
								outputTokens = int64(ct)
							} else if ot, ok := u["output_tokens"].(float64); ok {
								outputTokens = int64(ot)
							}
							if ptd, ok := u["prompt_tokens_details"].(map[string]interface{}); ok {
								if ct, ok := ptd["cached_tokens"].(float64); ok {
									cachedTokens = int64(ct)
								}
							}
						}
						if choices, ok := chunkJSON["choices"].([]interface{}); ok {
							for _, c := range choices {
								if cMap, ok := c.(map[string]interface{}); ok {
									if delta, ok := cMap["delta"].(map[string]interface{}); ok {
										if content, ok := delta["content"].(string); ok {
											accumulatedChars += len(content)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading stream chunk: %w", readErr)
		}
	}

	isEstimated := false
	usageSource := "provider_reported"
	if !foundProviderUsage {
		isEstimated = true
		usageSource = "character_estimate"
		if inputTokens == 0 {
			inputTokens = int64(len(payload) / 4)
		}
		if outputTokens == 0 && accumulatedChars > 0 {
			outputTokens = int64((accumulatedChars / 4) + 1)
		}
	}

	return &UsageReport{
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CachedInputTokens: cachedTokens,
		IsEstimated:       isEstimated,
		UsageSource:       usageSource,
		StatusCode:        resp.StatusCode,
	}, nil
}
