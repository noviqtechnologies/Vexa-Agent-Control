package routing

import (
	"context"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func TestValidateProfile_ValidAndInvalid(t *testing.T) {
	// Valid Profile
	valid := &model.RouteProfile{
		Name:            "Default Chat Profile",
		APIFamily:       "chat_completions",
		PrimaryProvider: "openai",
		PrimaryModel:    "gpt-4o",
		MaxAttempts:     2,
		DeadlineMs:      30000,
	}
	if err := ValidateProfile(valid); err != nil {
		t.Fatalf("expected valid profile to pass, got: %v", err)
	}

	// Invalid: Max Attempts > 2 (violates P0 NFR-REL-02)
	invalidAttempts := &model.RouteProfile{
		Name:            "Invalid 3 Attempts",
		APIFamily:       "chat_completions",
		PrimaryProvider: "openai",
		PrimaryModel:    "gpt-4o",
		MaxAttempts:     3,
	}
	if err := ValidateProfile(invalidAttempts); err == nil {
		t.Errorf("expected error for max_attempts > 2, got nil")
	}

	// Invalid: Missing primary model
	invalidPrimary := &model.RouteProfile{
		Name:            "Missing Primary",
		APIFamily:       "chat_completions",
		PrimaryProvider: "openai",
	}
	if err := ValidateProfile(invalidPrimary); err == nil {
		t.Errorf("expected error for missing primary model, got nil")
	}
}

func TestMatchScore_Priorities(t *testing.T) {
	exactProfile := &model.RouteProfile{
		APIFamily:  "chat_completions",
		MatchModel: "gpt-4o",
	}
	wildcardProfile := &model.RouteProfile{
		APIFamily:  "chat_completions",
		MatchModel: "gpt-*",
	}
	globalProfile := &model.RouteProfile{
		APIFamily:  "chat_completions",
		MatchModel: "*",
	}

	exactScore := MatchScore(exactProfile, "chat_completions", "gpt-4o")
	wildcardScore := MatchScore(wildcardProfile, "chat_completions", "gpt-4o")
	globalScore := MatchScore(globalProfile, "chat_completions", "gpt-4o")

	if exactScore != 100 {
		t.Errorf("expected exact match score 100, got %d", exactScore)
	}
	if wildcardScore != 50 {
		t.Errorf("expected wildcard match score 50, got %d", wildcardScore)
	}
	if globalScore != 10 {
		t.Errorf("expected global match score 10, got %d", globalScore)
	}

	if !(exactScore > wildcardScore && wildcardScore > globalScore) {
		t.Errorf("expected exactScore > wildcardScore > globalScore")
	}
}

func TestSimulate_Evaluation(t *testing.T) {
	profile := &model.RouteProfile{
		Name:             "OpenAI with Anthropic Fallback",
		APIFamily:        "chat_completions",
		MatchModel:       "gpt-*",
		PrimaryProvider:  "openai",
		PrimaryModel:     "gpt-4o",
		FallbackProvider: "anthropic",
		FallbackModel:    "claude-3-5-sonnet",
		MaxAttempts:      2,
		DeadlineMs:       30000,
	}

	fixtures := []SimulationFixture{
		{
			Name:           "Matching OpenAI Fixture",
			APIFamily:      "chat_completions",
			RequestedModel: "gpt-4o",
		},
		{
			Name:           "Non-Matching Messages Fixture",
			APIFamily:      "messages",
			RequestedModel: "claude-3-5-sonnet",
		},
	}

	report, err := Simulate(context.Background(), profile, fixtures)
	if err != nil {
		t.Fatalf("unexpected simulation error: %v", err)
	}

	if report.TotalFixtures != 2 {
		t.Errorf("expected 2 fixtures, got %d", report.TotalFixtures)
	}
	if report.Passed != 1 || report.Failed != 1 {
		t.Errorf("expected 1 passed and 1 failed, got %d passed, %d failed", report.Passed, report.Failed)
	}
}
