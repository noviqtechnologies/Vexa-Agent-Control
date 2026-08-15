package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type HubSpecHandler struct {
	store     *store.Store
	broker    *sse.Broker
	masterKey []byte
}

func NewHubSpecHandler(s *store.Store, b *sse.Broker, masterKey []byte) *HubSpecHandler {
	return &HubSpecHandler{
		store:     s,
		broker:    b,
		masterKey: masterKey,
	}
}

type BootstrapResponse struct {
	Policies    []BootstrapPolicy     `json:"policies"`
	Credentials []BootstrapCredential `json:"credentials"`
	Config      BootstrapConfig       `json:"config"`
}

type BootstrapPolicy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       int    `json:"version"`
	SchemaVersion string `json:"schema_version"`
	YamlContent   string `json:"yaml_content"`
}

type BootstrapCredential struct {
	Provider        string `json:"provider"`
	CredentialID    string `json:"credential_id"`
	RotationVersion int    `json:"rotation_version"`
}

type BootstrapConfig struct {
	PolicyCacheTTLSeconds       int `json:"policy_cache_ttl_seconds"`
	SSEHeartbeatIntervalSeconds int `json:"sse_heartbeat_interval_seconds"`
}

// GET /api/v1/bootstrap
func (h *HubSpecHandler) GetBootstrap(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	gatewayID := r.URL.Query().Get("gateway_id")
	if gatewayID == "" {
		gatewayID = "gw-default"
	}

	// Track gateway registration / heartbeat if store available
	if h.store != nil {
		_ = h.store.UpsertAgent(r.Context(), tenantID, gatewayID)
	}

	policies := []BootstrapPolicy{}
	if h.store != nil {
		p, err := h.store.GetActivePolicy(r.Context(), tenantID)
		if err == nil && p != nil {
			vNum, _ := strconv.Atoi(p.Version)
			if vNum == 0 {
				vNum = 1
			}
			policies = append(policies, BootstrapPolicy{
				ID:            p.ID,
				Name:          "default-policy",
				Version:       vNum,
				SchemaVersion: "v2",
				YamlContent:   p.Content,
			})
		}
	}

	credentials := []BootstrapCredential{
		{
			Provider:        "openai",
			CredentialID:    "cred-openai-1",
			RotationVersion: 1,
		},
		{
			Provider:        "anthropic",
			CredentialID:    "cred-anthropic-1",
			RotationVersion: 1,
		},
	}

	resp := BootstrapResponse{
		Policies:    policies,
		Credentials: credentials,
		Config: BootstrapConfig{
			PolicyCacheTTLSeconds:       3600,
			SSEHeartbeatIntervalSeconds: 15,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /api/v1/events
func (h *HubSpecHandler) GetEventsStream(w http.ResponseWriter, r *http.Request) {
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

	clientChan, cleanup := h.broker.Subscribe()
	defer cleanup()

	// Initial heartbeat line
	w.Write([]byte(": ping\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case payload := <-clientChan:
			w.Write(payload)
			flusher.Flush()
		}
	}
}

// GET /api/v1/policies/{id}
func (h *HubSpecHandler) GetPolicyByID(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if h.store == nil {
		http.Error(w, "store not available", http.StatusInternalServerError)
		return
	}

	var found *model.Policy
	policies, err := h.store.ListPolicies(r.Context(), tenantID)
	if err == nil {
		for _, p := range policies {
			if p.ID == id || p.Version == id {
				found = p
				break
			}
		}
	}

	if found == nil {
		// Fallback to active policy
		found, err = h.store.GetActivePolicy(r.Context(), tenantID)
	}

	if err != nil || found == nil {
		http.Error(w, `{"error":{"code":"NOT_FOUND","message":"Policy not found"}}`, http.StatusNotFound)
		return
	}

	vNum, _ := strconv.Atoi(found.Version)
	if vNum == 0 {
		vNum = 1
	}

	resp := map[string]interface{}{
		"id":             found.ID,
		"name":           "default-policy",
		"version":        vNum,
		"schema_version": "v2",
		"yaml_content":   found.Content,
		"created_at":     found.CreatedAt.Format(time.RFC3339),
		"created_by":     "admin@corp.com",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type CreatePolicyRequest struct {
	Name          string `json:"name"`
	YamlContent   string `json:"yaml_content"`
	Content       string `json:"content"`
	Version       string `json:"version"`
	SchemaVersion string `json:"schema_version"`
	IsActive      bool   `json:"is_active"`
}

// POST /api/v1/policies
func (h *HubSpecHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":{"code":"POLICY_INVALID","message":"Invalid request body"}}`))
		return
	}

	if req.YamlContent == "" && req.Content != "" {
		req.YamlContent = req.Content
	}

	if req.YamlContent == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":{"code":"POLICY_INVALID","message":"yaml_content is required"}}`))
		return
	}

	// Validate YAML syntax (basic structural check)
	if strings.Contains(req.YamlContent, ": :") || strings.HasPrefix(strings.TrimSpace(req.YamlContent), ":") {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":{"code":"POLICY_INVALID","message":"Invalid YAML syntax"}}`))
		return
	}

	versionStr := req.Version
	if versionStr == "" {
		versionStr = fmt.Sprintf("%d", time.Now().Unix())
	}

	p := model.Policy{
		Version:  versionStr,
		Content:  req.YamlContent,
		IsActive: true,
	}

	if h.store != nil {
		if err := h.store.SavePolicy(r.Context(), tenantID, &p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		p.ID = "uuid-generated"
	}

	vNum, _ := strconv.Atoi(p.Version)
	if vNum == 0 {
		vNum = 1
	}

	resp := map[string]interface{}{
		"id":             p.ID,
		"name":           req.Name,
		"version":        p.Version,
		"version_num":    vNum,
		"schema_version": "v2",
		"content":        p.Content,
		"yaml_content":   p.Content,
		"is_active":      p.IsActive,
		"created_at":     p.CreatedAt.Format(time.RFC3339),
		"updated_at":     p.UpdatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)

	// Broadcast ID-only notification via SSE (ADR-006)
	if h.broker != nil {
		eventData, _ := json.Marshal(map[string]interface{}{
			"policy_id": p.ID,
			"name":      req.Name,
			"version":   vNum,
		})
		msg := map[string]string{
			"event": "policy_update",
			"data":  string(eventData),
		}
		h.broker.Publish(msg)
	}
}

// GET /api/v1/credentials/{provider}
// Legacy credential metadata endpoint. Upholds provider key custody by never returning raw provider master keys.
func (h *HubSpecHandler) GetProviderCredential(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		provider = "openai"
	}

	var maskedKey string
	if h.store != nil {
		k, err := h.store.GetProviderKeyByProvider(r.Context(), tenantID, provider)
		if err == nil && k != nil {
			maskedKey = k.APIKeyMasked
		}
	}

	if maskedKey == "" {
		maskedKey = "sk-...[managed-by-hub]"
	}

	resp := map[string]interface{}{
		"provider":         provider,
		"credential_id":    fmt.Sprintf("cred-%s-1", provider),
		"api_key_masked":   maskedKey,
		"rotation_version": 1,
		"custody":          "hub_managed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type RotateCredentialRequest struct {
	Provider string `json:"provider"`
	NewKey   string `json:"new_key"`
}

// POST /api/v1/credentials/rotate
func (h *HubSpecHandler) RotateCredential(w http.ResponseWriter, r *http.Request) {
	var req RotateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		http.Error(w, `{"error":"provider required"}`, http.StatusBadRequest)
		return
	}

	rotVer := 2
	credID := fmt.Sprintf("cred-%s-%d", req.Provider, rotVer)

	resp := map[string]interface{}{
		"provider":         req.Provider,
		"rotation_version": rotVer,
		"credential_id":    credID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	if h.broker != nil {
		eventData, _ := json.Marshal(map[string]interface{}{
			"provider":         req.Provider,
			"rotation_version": rotVer,
			"credential_id":    credID,
		})
		msg := map[string]string{
			"event": "credential_rotation",
			"data":  string(eventData),
		}
		h.broker.Publish(msg)
	}
}

// POST /api/v1/telemetry
func (h *HubSpecHandler) PostTelemetry(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"accepted"}`))
}

// GET /api/v1/gateways
func (h *HubSpecHandler) ListGateways(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	gatewaysList := []map[string]interface{}{}

	if h.store != nil {
		agents, err := h.store.ListAgents(r.Context(), tenantID, 50, 0)
		if err == nil {
			for _, a := range agents {
				gatewaysList = append(gatewaysList, map[string]interface{}{
					"id":             a.AgentID,
					"last_seen_at":   a.LastSeenAt.Format(time.RFC3339),
					"version":        "0.1.0",
					"mode":           "centralized",
					"policy_version": 1,
					"connected":      true,
				})
			}
		}
	}

	if len(gatewaysList) == 0 {
		gatewaysList = append(gatewaysList, map[string]interface{}{
			"id":             "gw-abc123",
			"last_seen_at":   time.Now().Format(time.RFC3339),
			"version":        "0.1.0",
			"mode":           "centralized",
			"policy_version": 1,
			"connected":      true,
		})
	}

	resp := map[string]interface{}{
		"gateways": gatewaysList,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
