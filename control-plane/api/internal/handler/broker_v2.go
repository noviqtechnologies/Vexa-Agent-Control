package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type BrokerV2Handler struct {
	Store          *store.Store
	ProviderClient broker.ProviderClient
}

func NewBrokerV2Handler(st *store.Store, pc broker.ProviderClient) *BrokerV2Handler {
	return &BrokerV2Handler{
		Store:          st,
		ProviderClient: pc,
	}
}

type BrokerRequestPayload struct {
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Provider      string          `json:"provider"`
	ProjectRef    string          `json:"project_ref"`
	Model         string          `json:"model"`
	Protocol      string          `json:"protocol"`
	Stream        bool            `json:"stream"`
	Payload       json.RawMessage `json:"payload"`
}

// POST /api/v2/broker/llm-requests
func (h *BrokerV2Handler) HandleLLMRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	if principal.DeviceState != model.DeviceStateCompliant {
		http.Error(w, `{"error":{"code":"device_state_denied","message":"Device is not in COMPLIANT state"}}`, http.StatusForbidden)
		return
	}

	var req BrokerRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	// Forward request through provider adapter
	llmResp, err := h.ProviderClient.ForwardLLMRequest(
		r.Context(),
		req.Provider,
		req.Model,
		req.Stream,
		req.Payload,
		"SECRET_FROM_SECRET_MANAGER",
	)

	if err != nil {
		http.Error(w, `{"error":{"code":"upstream_provider_error"}}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(llmResp)
}
