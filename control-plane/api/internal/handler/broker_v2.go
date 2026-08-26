package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type BrokerV2Handler struct {
	Store          *store.Store
	ProviderClient broker.ProviderClient
	MasterKey      []byte
}

func NewBrokerV2Handler(st *store.Store, pc broker.ProviderClient, masterKey []byte) *BrokerV2Handler {
	return &BrokerV2Handler{
		Store:          st,
		ProviderClient: pc,
		MasterKey:      masterKey,
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

	// Look up and decrypt tenant provider key
	var apiKey string
	if h.Store != nil && len(h.MasterKey) > 0 {
		tenantID := principal.TenantID
		if tenantID == "" {
			tenantID = "00000000-0000-0000-0000-000000000001"
		}
		pk, err := h.Store.GetProviderKeyByProvider(r.Context(), tenantID, req.Provider)
		if err == nil && pk != nil && pk.APIKeyEncrypted != "" {
			decrypted, decErr := crypto.Decrypt(h.MasterKey, pk.APIKeyEncrypted)
			if decErr == nil {
				apiKey = decrypted
			}
		}
	}

	if apiKey == "" {
		apiKey = "MOCK"
	}

	// Forward request through provider adapter
	llmResp, err := h.ProviderClient.ForwardLLMRequest(
		r.Context(),
		req.Provider,
		req.Model,
		req.Stream,
		req.Payload,
		apiKey,
	)

	if err != nil {
		http.Error(w, `{"error":{"code":"upstream_provider_error","message":"`+err.Error()+`"}}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(llmResp)
}
