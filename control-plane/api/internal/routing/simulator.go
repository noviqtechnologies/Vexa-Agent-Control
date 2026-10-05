package routing

import (
	"context"
	"fmt"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// SimulationFixture defines a synthetic test request for route validation.
type SimulationFixture struct {
	Name            string   `json:"name"`
	APIFamily       string   `json:"api_family"`
	RequestedModel  string   `json:"requested_model"`
	RequestedRegion string   `json:"requested_region,omitempty"`
	AllowedModels   []string `json:"allowed_models,omitempty"`
}

// SimulationItemResult captures the evaluated decision for one fixture.
type SimulationItemResult struct {
	FixtureName      string            `json:"fixture_name"`
	Matched          bool              `json:"matched"`
	SelectedPrimary  string            `json:"selected_primary,omitempty"`
	SelectedFallback string            `json:"selected_fallback,omitempty"`
	DecisionVerdict  string            `json:"decision_verdict"` // ALLOW | DENY
	ReasonCode       string            `json:"reason_code"`
	CandidateReasons map[string]string `json:"candidate_reasons"`
}

// SimulationReport summarizes the batch fixture evaluation.
type SimulationReport struct {
	ProfileDigest string                 `json:"profile_digest"`
	TotalFixtures int                    `json:"total_fixtures"`
	Passed        int                    `json:"passed"`
	Failed        int                    `json:"failed"`
	Results       []SimulationItemResult `json:"results"`
}

// DefaultFixtures returns standard P0 evaluation fixtures.
func DefaultFixtures() []SimulationFixture {
	return []SimulationFixture{
		{
			Name:           "Standard OpenAI Chat Request",
			APIFamily:      "chat_completions",
			RequestedModel: "gpt-4o",
		},
		{
			Name:           "Anthropic Messages Request",
			APIFamily:      "messages",
			RequestedModel: "claude-3-5-sonnet",
		},
		{
			Name:           "Wildcard Match Request",
			APIFamily:      "chat_completions",
			RequestedModel: "gpt-4o-mini",
		},
		{
			Name:            "Restricted Region Request",
			APIFamily:       "chat_completions",
			RequestedModel:  "gpt-4o",
			RequestedRegion: "eu-west-1",
		},
	}
}

// Simulate evaluates a candidate route profile against fixtures.
func Simulate(ctx context.Context, p *model.RouteProfile, fixtures []SimulationFixture) (*SimulationReport, error) {
	if err := ValidateProfile(p); err != nil {
		return nil, fmt.Errorf("candidate profile validation failed: %w", err)
	}

	if len(fixtures) == 0 {
		fixtures = DefaultFixtures()
	}

	report := &SimulationReport{
		ProfileDigest: p.ContentDigest,
		TotalFixtures: len(fixtures),
		Results:       make([]SimulationItemResult, 0, len(fixtures)),
	}

	for _, fix := range fixtures {
		score := MatchScore(p, fix.APIFamily, fix.RequestedModel)
		res := SimulationItemResult{
			FixtureName:      fix.Name,
			Matched:          score >= 0,
			CandidateReasons: make(map[string]string),
		}

		if score < 0 {
			res.DecisionVerdict = "DENY"
			res.ReasonCode = ReasonNotConfigured
			res.CandidateReasons[fix.RequestedModel] = ReasonNotConfigured
			report.Failed++
		} else {
			// Check region restrictions
			regionAllowed := true
			if fix.RequestedRegion != "" && len(p.AllowedRegions) > 0 {
				regionAllowed = false
				for _, r := range p.AllowedRegions {
					if r == "*" || strings.EqualFold(r, fix.RequestedRegion) {
						regionAllowed = true
						break
					}
				}
			}

			if !regionAllowed {
				res.DecisionVerdict = "DENY"
				res.ReasonCode = ReasonWrongRegion
				res.CandidateReasons[fmt.Sprintf("%s/%s", p.PrimaryProvider, p.PrimaryModel)] = ReasonWrongRegion
				report.Failed++
			} else {
				res.DecisionVerdict = "ALLOW"
				res.ReasonCode = ReasonCandidateSelected
				res.SelectedPrimary = fmt.Sprintf("%s/%s", p.PrimaryProvider, p.PrimaryModel)
				res.CandidateReasons[res.SelectedPrimary] = ReasonCandidateSelected

				if p.FallbackProvider != "" && p.FallbackModel != "" {
					res.SelectedFallback = fmt.Sprintf("%s/%s", p.FallbackProvider, p.FallbackModel)
					res.CandidateReasons[res.SelectedFallback] = "fallback_candidate_eligible"
				}
				report.Passed++
			}
		}

		report.Results = append(report.Results, res)
	}

	return report, nil
}
