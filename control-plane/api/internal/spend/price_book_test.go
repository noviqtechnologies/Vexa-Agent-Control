package spend

import (
	"testing"
)

func TestPriceBook_CalculateReserve(t *testing.T) {
	item := PriceBookItem{
		Provider:                       "openai",
		ModelSelector:                  "gpt-4o",
		InputRateMicrocentsPerMillion:  250_000_000, // $2.50 / 1M
		OutputRateMicrocentsPerMillion: 1_000_000_000, // $10.00 / 1M
	}

	// 1,000 input tokens, 2,000 max output tokens
	// Input: ceil(1000 * 250,000,000 / 1,000,000) = 250,000 microcents ($0.0025)
	// Output: ceil(2000 * 1,000,000,000 / 1,000,000) = 2,000,000 microcents ($0.02)
	// Total reserve: 2,250,000 microcents ($0.0225)
	reserve, err := item.CalculateReserve(1000, 2000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := MoneyMicrocents(2_250_000)
	if reserve != expected {
		t.Errorf("got reserve = %d, want %d", reserve, expected)
	}

	// Ceiling rounding test with non-round token counts:
	// 3 tokens input @ $2.50/M = ceil(3 * 250,000,000 / 1,000,000) = ceil(750) = 750
	// 5 tokens output @ $10.00/M = ceil(5 * 1,000,000,000 / 1,000,000) = 5000
	// Total = 5750 microcents
	reserve, err = item.CalculateReserve(3, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reserve != MoneyMicrocents(5750) {
		t.Errorf("got reserve = %d, want 5750", reserve)
	}

	// Missing / zero max output tokens should return error
	_, err = item.CalculateReserve(100, 0)
	if err == nil {
		t.Errorf("expected error for 0 max_output_tokens, got nil")
	}

	// Negative input tokens should return error
	_, err = item.CalculateReserve(-10, 100)
	if err == nil {
		t.Errorf("expected error for negative input tokens, got nil")
	}
}

func TestPriceBook_CalculateSettlement(t *testing.T) {
	item := PriceBookItem{
		Provider:                            "openai",
		ModelSelector:                       "gpt-4o",
		InputRateMicrocentsPerMillion:       250_000_000,  // $2.50 / 1M
		OutputRateMicrocentsPerMillion:      1_000_000_000, // $10.00 / 1M
		CachedInputRateMicrocentsPerMillion: 125_000_000,  // $1.25 / 1M
	}

	// 1,000 total input (with 400 cached), 500 output
	// Non-cached input: 600 * 250,000,000 / 1,000,000 = 150,000 microcents
	// Cached input: 400 * 125,000,000 / 1,000,000 = 50,000 microcents
	// Output: 500 * 1,000,000,000 / 1,000,000 = 500,000 microcents
	// Total: 700,000 microcents ($0.007)
	cost, err := item.CalculateSettlement(1000, 500, 400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := MoneyMicrocents(700_000)
	if cost != expected {
		t.Errorf("got cost = %d, want %d", cost, expected)
	}
}

func TestMatchModel(t *testing.T) {
	if !MatchModel("gpt-4o", "gpt-4o") {
		t.Errorf("exact match failed")
	}
	if !MatchModel("gpt-4o*", "gpt-4o-mini") {
		t.Errorf("wildcard match failed")
	}
	if !MatchModel("*", "anything") {
		t.Errorf("catch-all match failed")
	}
	if MatchModel("gpt-4o", "claude-3") {
		t.Errorf("mismatched model returned true")
	}
}
