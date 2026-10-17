package handler

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type PolicyMgmtHandler struct {
	store      *store.Store
	broker     *sse.Broker
	signingKey ed25519.PrivateKey
}

func NewPolicyMgmtHandler(s *store.Store, b *sse.Broker) *PolicyMgmtHandler {
	return &PolicyMgmtHandler{store: s, broker: b}
}

func (h *PolicyMgmtHandler) SetSigningKey(k ed25519.PrivateKey) {
	h.signingKey = k
}

// getSigningKeyOrFail returns the policy signing key from a configured, independently managed source.
//
// PRD FR-006: The policy signing key must be separately protected from gateway auth and session secrets.
// This function enforces that contract by accepting ONLY:
//   1. An explicitly injected key (set via SetSigningKey, e.g. from a KMS/HSM provider)
//   2. POLICY_SIGNING_PRIVATE_KEY env variable (explicit, separately managed)
//
// REMOVED fallbacks (PRD Phase 2 — these made policy signing meaningless as independent authority):
//   - POLICY_READ_SECRET derivation  — gateway read secret ≠ independent signing authority
//   - GATEWAY_SECRET derivation      — shared operational secret ≠ policy signing key
//   - "default-vexa-hub-policy-signing-key" hard-coded  — public value ≠ cryptographic authority
//
// In managed/team mode, callers MUST check this error and fail startup if signing is unavailable.
func (h *PolicyMgmtHandler) getSigningKeyOrFail() (ed25519.PrivateKey, error) {
	// Priority 1: explicitly injected key (from KMS/HSM provider via SetSigningKey)
	if len(h.signingKey) == ed25519.PrivateKeySize {
		return h.signingKey, nil
	}

	// Priority 2: POLICY_SIGNING_PRIVATE_KEY — must be configured explicitly and separately
	if keyHex := os.Getenv("POLICY_SIGNING_PRIVATE_KEY"); keyHex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil {
			return nil, fmt.Errorf("signing_key_decode_error: POLICY_SIGNING_PRIVATE_KEY is not valid hex: %w", err)
		}
		if len(b) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b), nil
		} else if len(b) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(b), nil
		}
		return nil, fmt.Errorf("signing_key_size_error: POLICY_SIGNING_PRIVATE_KEY must be %d or %d bytes (got %d)",
			ed25519.PrivateKeySize, ed25519.SeedSize, len(b))
	}

	// No valid signing authority found — fail closed.
	// A bundle signed with a derived or hard-coded key provides no meaningful trust guarantee.
	return nil, fmt.Errorf("signing_authority_missing: no POLICY_SIGNING_PRIVATE_KEY configured. " +
		"Managed/team mode requires an explicitly configured, independently managed signing key. " +
		"See docs/guides/managed-mode-bootstrap.md for setup instructions. " +
		"Do NOT set POLICY_READ_SECRET or GATEWAY_SECRET as substitutes.")
}

// getSigningKey is retained for backward compatibility in non-managed contexts.
// It calls getSigningKeyOrFail and panics only in development mode if no key is found.
// Production callers (managed mode) must use getSigningKeyOrFail directly.
func (h *PolicyMgmtHandler) getSigningKey() (ed25519.PrivateKey, error) {
	return h.getSigningKeyOrFail()
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

func (h *PolicyMgmtHandler) GetActiveBundle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}

	policy, err := h.store.GetActivePolicy(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policy == nil || policy.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"no_active_policy"}`))
		return
	}

	privKey, err := h.getSigningKey()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"signing_key_error: %v"}`, err), http.StatusInternalServerError)
		return
	}

	var revision uint64 = 1
	if policy.UpdatedAt.Unix() > 0 {
		revision = uint64(policy.UpdatedAt.Unix())
	}

	policyID := policy.ID
	if policyID == "" {
		policyID = fmt.Sprintf("tenant-%s-active", tenantID)
	}

	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	bundle, err := crypto.SignPolicyBundle(privKey, policyID, revision, policy.Content, &expiry)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"bundle_signing_failed: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
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
	w.Header().Set("X-Accel-Buffering", "no")

	clientChan, cleanup := h.broker.SubscribeTenant(tenantID)
	defer cleanup()

	// Initial heartbeat line
	w.Write([]byte(": ping\n\n"))
	flusher.Flush()

	// Send initial active policy if available
	policy, err := h.store.GetActivePolicy(r.Context(), tenantID)
	if err == nil && policy != nil {
		w.Write(formatSSE("policy_update", policy.Content))
		flusher.Flush()
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
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
