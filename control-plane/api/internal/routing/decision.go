package routing

import (
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// Reason codes for route evaluation and candidate filtering.
const (
	ReasonCandidateSelected     = "candidate_selected"
	ReasonNotConfigured         = "not_configured"
	ReasonNotAllowed            = "not_allowed"
	ReasonWrongRegion           = "wrong_region"
	ReasonUnsupportedAPIFeature = "unsupported_api_feature"
	ReasonCredentialUnavailable = "credential_unavailable"
	ReasonCircuitOpen           = "circuit_open"
	ReasonSpendCapExceeded      = "spend_cap_exceeded"
	ReasonDeadlineExceeded      = "deadline_exceeded"
)

// ExplainableRouteDecision documents candidate evaluation.
type ExplainableRouteDecision = model.ExplainableRouteDecision

// NewRouteDecision initializes an explainable route decision structure.
func NewRouteDecision(tenantID, apiFamily, requestedModel string) *ExplainableRouteDecision {
	return &ExplainableRouteDecision{
		TenantID:         tenantID,
		RequestedAPI:     apiFamily,
		RequestedModel:   requestedModel,
		CandidateReasons: make(map[string]string),
	}
}
