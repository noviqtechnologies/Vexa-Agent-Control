package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MockFaultScenario defines simulated failure conditions.
type MockFaultScenario struct {
	FaultType    string        // ok | 429 | 503 | 502 | timeout | malformed | stream_break_chunk_2
	RetryAfter   int           // seconds
	Delay        time.Duration // simulated latency
	InputTokens  int64
	OutputTokens int64
}

// MockFaultProviderClient implements ProviderClient with deterministic fault injection.
type MockFaultProviderClient struct {
	DefaultScenario MockFaultScenario
	ScenarioMap     map[string]MockFaultScenario // key: provider/model or header tag
}

// NewMockFaultProviderClient creates a mock provider.
func NewMockFaultProviderClient() *MockFaultProviderClient {
	return &MockFaultProviderClient{
		DefaultScenario: MockFaultScenario{
			FaultType:    "ok",
			InputTokens:  15,
			OutputTokens: 8,
		},
		ScenarioMap: make(map[string]MockFaultScenario),
	}
}

// SetScenario sets a fault scenario for a specific target key.
func (m *MockFaultProviderClient) SetScenario(key string, s MockFaultScenario) {
	if m.ScenarioMap == nil {
		m.ScenarioMap = make(map[string]MockFaultScenario)
	}
	m.ScenarioMap[key] = s
}

func (m *MockFaultProviderClient) resolveScenario(provider, model string) MockFaultScenario {
	key := fmt.Sprintf("%s/%s", strings.ToLower(provider), strings.ToLower(model))
	if s, ok := m.ScenarioMap[key]; ok {
		return s
	}
	if s, ok := m.ScenarioMap[strings.ToLower(provider)]; ok {
		return s
	}
	return m.DefaultScenario
}

func (m *MockFaultProviderClient) ForwardLLMRequest(
	ctx context.Context,
	provider, model string,
	stream bool,
	payload json.RawMessage,
	apiKey string,
) (*LLMResponse, *UsageReport, error) {
	scenario := m.resolveScenario(provider, model)

	if scenario.Delay > 0 {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(scenario.Delay):
		}
	}

	switch scenario.FaultType {
	case "429":
		body := []byte(fmt.Sprintf(`{"error":{"message":"Rate limit exceeded","code":"rate_limit_exceeded","retry_after":%d}}`, scenario.RetryAfter))
		return nil, nil, &UpstreamHTTPError{
			StatusCode: http.StatusTooManyRequests,
			Body:       body,
		}

	case "503":
		body := []byte(`{"error":{"message":"Service Unavailable","code":"service_unavailable"}}`)
		return nil, nil, &UpstreamHTTPError{
			StatusCode: http.StatusServiceUnavailable,
			Body:       body,
		}

	case "502":
		body := []byte(`{"error":{"message":"Bad Gateway","code":"bad_gateway"}}`)
		return nil, nil, &UpstreamHTTPError{
			StatusCode: http.StatusBadGateway,
			Body:       body,
		}

	case "timeout":
		return nil, nil, errors.New("upstream provider connection timed out: i/o timeout")

	case "malformed":
		return &LLMResponse{
			Response: json.RawMessage(`{not-a-valid-json`),
		}, &UsageReport{StatusCode: 200}, nil

	default: // ok
		inToks := scenario.InputTokens
		if inToks <= 0 {
			inToks = 20
		}
		outToks := scenario.OutputTokens
		if outToks <= 0 {
			outToks = 10
		}

		mockResp := map[string]interface{}{
			"id":      fmt.Sprintf("chatcmpl-mock-%d", time.Now().UnixNano()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": fmt.Sprintf("Deterministic response from %s/%s", provider, model),
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int64{
				"prompt_tokens":     inToks,
				"completion_tokens": outToks,
				"total_tokens":      inToks + outToks,
			},
		}

		rawBytes, _ := json.Marshal(mockResp)
		usageRep := &UsageReport{
			InputTokens:       inToks,
			OutputTokens:      outToks,
			CachedInputTokens: 0,
			IsEstimated:       false,
			UsageSource:       "provider_reported",
			StatusCode:        200,
		}

		return &LLMResponse{
			Usage: map[string]interface{}{
				"prompt_tokens":     inToks,
				"completion_tokens": outToks,
				"total_tokens":      inToks + outToks,
			},
			Response: rawBytes,
		}, usageRep, nil
	}
}

func (m *MockFaultProviderClient) ForwardLLMRequestStream(
	ctx context.Context,
	provider, model string,
	payload json.RawMessage,
	apiKey string,
	onChunk func(chunk []byte) error,
) (*UsageReport, error) {
	scenario := m.resolveScenario(provider, model)

	if scenario.FaultType == "503" {
		return nil, &UpstreamHTTPError{
			StatusCode: http.StatusServiceUnavailable,
			Body:       []byte(`{"error":{"message":"Service Unavailable"}}`),
		}
	}
	if scenario.FaultType == "429" {
		return nil, &UpstreamHTTPError{
			StatusCode: http.StatusTooManyRequests,
			Body:       []byte(`{"error":{"message":"Rate limit exceeded"}}`),
		}
	}
	if scenario.FaultType == "timeout" {
		return nil, errors.New("upstream connection timeout")
	}

	// Emit chunk 1
	chunk1 := []byte(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"Hello from %s/\"}}]}\n\n", provider))
	if err := onChunk(chunk1); err != nil {
		return nil, err
	}

	// Check for mid-stream break scenario
	if scenario.FaultType == "stream_break_chunk_2" {
		return &UsageReport{
			InputTokens:  10,
			OutputTokens: 2,
			StatusCode:   500,
		}, errors.New("upstream connection closed unexpectedly mid-stream")
	}

	// Emit chunk 2 & done
	chunk2 := []byte(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"%s!\"}}]}\n\n", model))
	if err := onChunk(chunk2); err != nil {
		return nil, err
	}
	_ = onChunk([]byte("data: [DONE]\n\n"))

	return &UsageReport{
		InputTokens:  scenario.InputTokens,
		OutputTokens: scenario.OutputTokens,
		StatusCode:   200,
		UsageSource:  "provider_reported",
	}, nil
}
