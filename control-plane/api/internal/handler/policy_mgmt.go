package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type PolicyMgmtHandler struct {
	store  *store.Store
	broker *sse.Broker
}

func NewPolicyMgmtHandler(s *store.Store, b *sse.Broker) *PolicyMgmtHandler {
	return &PolicyMgmtHandler{store: s, broker: b}
}

func writeUnauthorizedTenantError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    "unauthorized_tenant_required",
			"message": "Authenticated tenant principal is required for this operation",
		},
	})
}

func (h *PolicyMgmtHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	policies, err := h.store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policies == nil {
		policies = []*model.Policy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (h *PolicyMgmtHandler) GetActive(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	var policy *model.Policy
	var err error
	
	if r.URL.Query().Get("raw") == "true" {
		policy, err = h.store.GetRawActivePolicy(r.Context(), tenantID)
	} else {
		policy, err = h.store.GetActivePolicy(r.Context(), tenantID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"no_active_policy"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *PolicyMgmtHandler) Save(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	var req struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Content     string `json:"content"`
		YamlContent string `json:"yaml_content"`
		IsActive    bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	content := req.Content
	if content == "" && req.YamlContent != "" {
		content = req.YamlContent
	}
	if content == "" {
		http.Error(w, "content or yaml_content is required", http.StatusBadRequest)
		return
	}

	version := req.Version
	if version == "" {
		version = "v1.0.0"
	}

	p := model.Policy{
		Version:  version,
		Content:  content,
		IsActive: true,
	}
	if err := h.store.SavePolicy(r.Context(), tenantID, &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)

	// Broadcast the new policy over SSE to connected gateways for this tenant
	if h.broker != nil {
		h.broker.PublishTenant(tenantID, formatSSE("policy_update", p.Content))
	}
}

func formatSSE(event, data string) []byte {
	var sb strings.Builder
	sb.WriteString("event: " + event + "\n")
	for _, line := range strings.Split(data, "\n") {
		sb.WriteString("data: " + line + "\n")
	}
	sb.WriteString("\n")
	return []byte(sb.String())
}

func (h *PolicyMgmtHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}

	if h.broker == nil {
		http.Error(w, "SSE broker not configured", http.StatusInternalServerError)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan, cleanup := h.broker.SubscribeTenant(tenantID)
	defer cleanup()
	// Send initial active policy if available
	policy, err := h.store.GetActivePolicy(r.Context(), tenantID)
	if err == nil && policy != nil {
		w.Write(formatSSE("policy_update", policy.Content))
		flusher.Flush()
	}

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case payload := <-clientChan:
			w.Write(payload)
			flusher.Flush()
		}
	}
}
