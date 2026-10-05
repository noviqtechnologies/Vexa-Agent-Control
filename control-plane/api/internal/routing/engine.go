package routing

import (
	"context"
	"fmt"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// TargetCandidate represents an evaluated dispatch target.
type TargetCandidate struct {
	Type     string // primary | fallback
	Provider string
	Model    string
}

// RouteResult captures the authoritative route decision for an incoming request.
type RouteResult struct {
	Profile      *model.RouteProfile
	Primary      TargetCandidate
	Fallback     *TargetCandidate
	Decision     *model.ExplainableRouteDecision
	MaxAttempts  int
	DeadlineMs   int
	RetryClasses []string
}

// RouterDataStore provides route query capabilities.
type RouterDataStore interface {
	GetActiveRouteProfile(ctx context.Context, orgID, apiFamily, modelName string) (*model.RouteProfile, error)
}

// Engine encapsulates routing resolution logic.
type Engine struct {
	store RouterDataStore
}

// NewEngine constructs a routing engine.
func NewEngine(s RouterDataStore) *Engine {
	return &Engine{store: s}
}

// ResolveRoute resolves the active route profile and candidates for an incoming broker request.
func (e *Engine) ResolveRoute(
	ctx context.Context,
	tenantID, apiFamily, requestedModel, requestedRegion string,
) (*RouteResult, error) {
	if apiFamily == "" {
		apiFamily = "chat_completions"
	}

	decision := NewRouteDecision(tenantID, apiFamily, requestedModel)

	if e.store == nil {
		// Default direct fallback if store is uninitialized (e.g. standalone test)
		decision.SelectedPrimary = fmt.Sprintf("openai/%s", requestedModel)
		decision.AddCandidateOutcome("openai", requestedModel, ReasonCandidateSelected)
		return &RouteResult{
			Primary: TargetCandidate{
				Type:     "primary",
				Provider: "openai",
				Model:    requestedModel,
			},
			Decision:     decision,
			MaxAttempts:  2,
			DeadlineMs:   30000,
			RetryClasses: []string{"502", "503", "504", "429", "connect_timeout", "dns_error"},
		}, nil
	}

	profile, err := e.store.GetActiveRouteProfile(ctx, tenantID, apiFamily, requestedModel)
	if err != nil {
		return nil, fmt.Errorf("failed to query active route profile: %w", err)
	}

	// If no profile found, construct default route with requested model
	if profile == nil {
		prov := "openai"
		if strings.Contains(strings.ToLower(requestedModel), "claude") {
			prov = "anthropic"
		} else if strings.Contains(strings.ToLower(requestedModel), "gemini") {
			prov = "google"
		}
		decision.SelectedPrimary = fmt.Sprintf("%s/%s", prov, requestedModel)
		decision.AddCandidateOutcome(prov, requestedModel, ReasonCandidateSelected)
		return &RouteResult{
			Primary: TargetCandidate{
				Type:     "primary",
				Provider: prov,
				Model:    requestedModel,
			},
			Decision:     decision,
			MaxAttempts:  1,
			DeadlineMs:   30000,
			RetryClasses: []string{"502", "503", "504", "429", "connect_timeout", "dns_error"},
		}, nil
	}

	decision.RouteProfileID = profile.ID
	decision.RouteVersion = profile.Version
	decision.SelectedPrimary = fmt.Sprintf("%s/%s", profile.PrimaryProvider, profile.PrimaryModel)
	decision.AddCandidateOutcome(profile.PrimaryProvider, profile.PrimaryModel, ReasonCandidateSelected)

	res := &RouteResult{
		Profile: profile,
		Primary: TargetCandidate{
			Type:     "primary",
			Provider: profile.PrimaryProvider,
			Model:    profile.PrimaryModel,
		},
		Decision:     decision,
		MaxAttempts:  profile.MaxAttempts,
		DeadlineMs:   profile.DeadlineMs,
		RetryClasses: profile.RetryClasses,
	}

	if profile.FallbackProvider != "" && profile.FallbackModel != "" {
		res.Fallback = &TargetCandidate{
			Type:     "fallback",
			Provider: profile.FallbackProvider,
			Model:    profile.FallbackModel,
		}
		decision.SelectedFallback = fmt.Sprintf("%s/%s", profile.FallbackProvider, profile.FallbackModel)
		decision.AddCandidateOutcome(profile.FallbackProvider, profile.FallbackModel, "fallback_candidate_eligible")
	}

	return res, nil
}
