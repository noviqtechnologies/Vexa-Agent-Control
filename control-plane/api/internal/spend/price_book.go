package spend

import (
	"context"
	"errors"
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

// GetActivePriceBookVersionID returns the most recently published active price book version ID.
func (s *Store) GetActivePriceBookVersionID(ctx context.Context) string {
	if s.pool == nil {
		return "price-book-v1"
	}
	var versionID string
	err := s.pool.QueryRow(ctx, `
		SELECT price_book_version_id FROM price_book_versions
		ORDER BY published_at DESC LIMIT 1
	`).Scan(&versionID)
	if err != nil || versionID == "" {
		return "price-book-v1"
	}
	return versionID
}

// GetPriceBookItem queries the exact or wildcard model rate in the specified price book.
// Returns pgx.ErrNoRows if no pricing rule matches. Never returns synthetic fallback rates.
func (s *Store) GetPriceBookItem(ctx context.Context, versionID, provider, model string) (*PriceBookItem, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	var item PriceBookItem
	err := s.pool.QueryRow(ctx, `
		SELECT item_id, price_book_version_id, provider, model_selector,
		       input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million
		FROM price_book_items
		WHERE price_book_version_id = $1 AND LOWER(provider) = LOWER($2) AND (
			model_selector = $3 
			OR model_selector = '*' 
			OR ($3 LIKE REPLACE(model_selector, '*', '%'))
		)
		ORDER BY 
			CASE WHEN model_selector = $3 THEN 1 WHEN model_selector != '*' THEN 2 ELSE 3 END
		LIMIT 1
	`, versionID, provider, model).Scan(
		&item.ItemID, &item.PriceBookVersionID, &item.Provider, &item.ModelSelector,
		&item.InputRateMicrocentsPerMillion, &item.OutputRateMicrocentsPerMillion,
		&item.CachedInputRateMicrocentsPerMillion,
	)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

