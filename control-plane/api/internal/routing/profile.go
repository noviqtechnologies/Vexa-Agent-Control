package routing

import (
	"errors"
	"fmt"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var (
	ErrNoMatchingRoute     = errors.New("no matching route profile found")
	ErrMaxAttemptsExceeded = errors.New("max attempts must be between 1 and 2")
	ErrInvalidAPIFamily    = errors.New("unsupported api family")
	ErrPrimaryRequired     = errors.New("primary provider and model are required")
)

// SupportedAPIFamilies lists the protocol families supported by Vexa LLM Router.
var SupportedAPIFamilies = map[string]bool{
	"chat_completions": true,
	"messages":         true,
	"responses":        true,
}

// SupportedProviders lists the provider adapters verified in the central broker for P0.
var SupportedProviders = map[string]bool{
	"openai":    true,
	"anthropic": true,
	"google":    true,
	"gemini":    true,
}

// RouteProfile represents an immutable routing rule set.
type RouteProfile = model.RouteProfile

// MatchScore evaluates how well a route profile matches a request.
func MatchScore(p *RouteProfile, apiFamily, modelName string) int {
	if p.APIFamily != apiFamily && p.APIFamily != "*" {
		return -1
	}

	matchMod := strings.ToLower(p.MatchModel)
	reqMod := strings.ToLower(modelName)

	if matchMod == reqMod {
		return 100 // Exact model match
	}
	if matchMod == "*" {
		return 10 // Global wildcard match
	}
	if strings.HasSuffix(matchMod, "*") && strings.HasPrefix(reqMod, strings.TrimSuffix(matchMod, "*")) {
		return 50 // Prefix wildcard match (e.g. gpt-*)
	}
	return -1
}

// ValidateProfile enforces P0 safety invariants on route configuration.
func ValidateProfile(p *RouteProfile) error {
	if p.Name == "" {
		return errors.New("route profile name is required")
	}
	if p.APIFamily == "" {
		p.APIFamily = "chat_completions"
	}
	if !SupportedAPIFamilies[p.APIFamily] {
		return fmt.Errorf("%w: %s", ErrInvalidAPIFamily, p.APIFamily)
	}
	if p.PrimaryProvider == "" || p.PrimaryModel == "" {
		return ErrPrimaryRequired
	}
	if !SupportedProviders[strings.ToLower(p.PrimaryProvider)] {
		return fmt.Errorf("unsupported primary provider adapter: %s (supported: openai, anthropic, google, gemini)", p.PrimaryProvider)
	}

	if p.FallbackProvider != "" || p.FallbackModel != "" {
		if p.FallbackProvider == "" || p.FallbackModel == "" {
			return errors.New("both fallback provider and model must be specified together")
		}
		if !SupportedProviders[strings.ToLower(p.FallbackProvider)] {
			return fmt.Errorf("unsupported fallback provider adapter: %s", p.FallbackProvider)
		}
	}

	if p.MaxAttempts < 1 || p.MaxAttempts > 2 {
		return ErrMaxAttemptsExceeded
	}
	if p.DeadlineMs <= 0 {
		p.DeadlineMs = 30000
	}
	if p.DeadlineMs > 120000 {
		return errors.New("deadline_ms cannot exceed 120,000 ms (2 minutes)")
	}
	if len(p.RetryClasses) == 0 {
		p.RetryClasses = []string{"502", "503", "504", "429", "connect_timeout", "dns_error"}
	}
	return nil
}
