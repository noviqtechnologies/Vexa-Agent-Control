package spend

import (
	"fmt"
	"strings"
	"time"
)

// PriceBookItem represents an audited rate item in USD microcents per 1M tokens.
type PriceBookItem struct {
	ItemID                         string          `json:"item_id"`
	PriceBookVersionID             string          `json:"price_book_version_id"`
	Provider                       string          `json:"provider"`
	ModelSelector                  string          `json:"model_selector"`
	InputRateMicrocentsPerMillion  MoneyMicrocents `json:"input_rate_microcents_per_million"`
	OutputRateMicrocentsPerMillion MoneyMicrocents `json:"output_rate_microcents_per_million"`
	CachedInputRateMicrocentsPerMillion MoneyMicrocents `json:"cached_input_rate_microcents_per_million"`
	EffectiveFrom                  time.Time       `json:"effective_from"`
	EffectiveTo                    *time.Time      `json:"effective_to,omitempty"`
}

// CalculateReserve computes the maximum bounded cost in integer microcents.
// Formula: ceil(input_tokens * input_rate / 1,000,000) + ceil(max_output_tokens * output_rate / 1,000,000)
func (item *PriceBookItem) CalculateReserve(inputTokens, maxOutputTokens int64) (MoneyMicrocents, error) {
	if inputTokens < 0 {
		return 0, fmt.Errorf("input tokens cannot be negative: %d", inputTokens)
	}
	if maxOutputTokens <= 0 {
		return 0, fmt.Errorf("%s: max_output_tokens must be greater than 0", ErrCodeOutputBoundMissing)
	}

	inputCost := CeilDiv(inputTokens*int64(item.InputRateMicrocentsPerMillion), 1_000_000)
	outputCost := CeilDiv(maxOutputTokens*int64(item.OutputRateMicrocentsPerMillion), 1_000_000)

	return MoneyMicrocents(inputCost + outputCost), nil
}

// CalculateSettlement computes actual usage cost in integer microcents.
func (item *PriceBookItem) CalculateSettlement(inputTokens, outputTokens, cachedInputTokens int64) (MoneyMicrocents, error) {
	if inputTokens < 0 || outputTokens < 0 || cachedInputTokens < 0 {
		return 0, fmt.Errorf("token usage counts cannot be negative")
	}

	// Normal non-cached input tokens
	effectiveInputTokens := inputTokens
	if cachedInputTokens > 0 && cachedInputTokens <= effectiveInputTokens {
		effectiveInputTokens -= cachedInputTokens
	}

	inputCost := CeilDiv(effectiveInputTokens*int64(item.InputRateMicrocentsPerMillion), 1_000_000)
	outputCost := CeilDiv(outputTokens*int64(item.OutputRateMicrocentsPerMillion), 1_000_000)
	cachedCost := CeilDiv(cachedInputTokens*int64(item.CachedInputRateMicrocentsPerMillion), 1_000_000)

	return MoneyMicrocents(inputCost + outputCost + cachedCost), nil
}

// CeilDiv performs integer division with ceiling rounding: ceil(a / b)
func CeilDiv(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

// NormalizeModelName matches wildcard model names or exact names
func MatchModel(pattern, model string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	model = strings.TrimSpace(strings.ToLower(model))
	if pattern == "*" || pattern == model {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(model, prefix)
	}
	return false
}
