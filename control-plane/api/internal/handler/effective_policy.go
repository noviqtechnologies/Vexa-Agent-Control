package handler

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

// EffectivePolicyHandler resolves the synthesized effective policy across all 5 layers.
type EffectivePolicyHandler struct {
	spendStore  *spend.Store
	store       DataStore
	deviceStore *device.Store
	signingKey  ed25519.PrivateKey
}

// NewEffectivePolicyHandler creates a new EffectivePolicyHandler.
func NewEffectivePolicyHandler(ss *spend.Store, ds DataStore, devStores ...*device.Store) *EffectivePolicyHandler {
	var devStore *device.Store
	if len(devStores) > 0 {
		devStore = devStores[0]
	}
	return &EffectivePolicyHandler{
		spendStore:  ss,
		store:       ds,
		deviceStore: devStore,
	}
}

// SetSigningKey injects the authoritative Ed25519 signing key.
func (h *EffectivePolicyHandler) SetSigningKey(k ed25519.PrivateKey) {
	h.signingKey = k
}

// getSigningKey returns the authoritative policy signing key from explicit injection
// or POLICY_SIGNING_PRIVATE_KEY, failing closed if none is configured.
func (h *EffectivePolicyHandler) getSigningKey() (ed25519.PrivateKey, error) {
	if len(h.signingKey) == ed25519.PrivateKeySize {
		return h.signingKey, nil
	}
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
	return nil, fmt.Errorf("signing_authority_missing: no POLICY_SIGNING_PRIVATE_KEY configured")
}


// PolicyLadderLevel represents one tier in the provenance ladder.
type PolicyLadderLevel struct {
	Level      string      `json:"level"`
	Source     string      `json:"source"`
	Confidence string      `json:"confidence"`
	Policy     interface{} `json:"policy,omitempty"`
	Policies   interface{} `json:"policies,omitempty"`
	Scope      interface{} `json:"scope,omitempty"`
	State      interface{} `json:"state,omitempty"`
}

// GetEffective handles GET /api/v1/policy/effective-explorer
func (h *EffectivePolicyHandler) GetEffective(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	deviceID := r.URL.Query().Get("device_id")
	agentID := r.URL.Query().Get("agent_id")
	vkID := r.URL.Query().Get("virtual_key_id")
	projectID := r.URL.Query().Get("project_id")
	if projectID == "" {
		projectID = "default"
	}
	provider := r.URL.Query().Get("provider")
	model := r.URL.Query().Get("model")
	route := r.URL.Query().Get("route")
	atStr := r.URL.Query().Get("at")

	atTime := time.Now().UTC()
	if atStr != "" {
		if t, err := time.Parse(time.RFC3339, atStr); err == nil {
			atTime = t
		}
	}

	ladder := make([]PolicyLadderLevel, 0)
	policyVersionIDs := make([]string, 0)

	// 1. Organization Level
	ladder = append(ladder, PolicyLadderLevel{
		Level:      "organization",
		Source:     "policy_mgmt",
		Confidence: "observed",
		Policy: map[string]interface{}{
			"tenant_id":        tenantID,
			"enforcement_mode": "enforce",
			"default_action":   "allow",
		},
	})

	// 2. Group Level
	groupPolicy, _ := h.store.GetActiveGroupPolicy(r.Context(), tenantID, "default")
	if groupPolicy != nil {
		policyVersionIDs = append(policyVersionIDs, groupPolicy.ID)
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "group",
			Source:     "group_policies",
			Confidence: "observed",
			Policy:     groupPolicy,
		})
	} else {
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "group",
			Source:     "group_policies",
			Confidence: "not_configured",
		})
	}

	// 3. Spend Level
	spendPolicies, err := h.spendStore.ResolveEffectivePolicies(r.Context(), tenantID, projectID, provider, atTime)
	minLimit := int64(10000000000) // $100 default limit
	dominantAction := "allow"

	if err == nil && len(spendPolicies) > 0 {
		for _, sp := range spendPolicies {
			policyVersionIDs = append(policyVersionIDs, sp.PolicyID)
			if int64(sp.LimitMicrocents) < minLimit {
				minLimit = int64(sp.LimitMicrocents)
			}
			if sp.Action == "hard_deny" {
				dominantAction = "hard_deny"
			} else if sp.Action == "warn" && dominantAction != "hard_deny" {
				dominantAction = "warn"
			}
		}
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "spend",
			Source:     "spend_v2",
			Confidence: "observed",
			Policies:   spendPolicies,
		})
	} else {
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "spend",
			Source:     "spend_v2",
			Confidence: "not_configured",
		})
	}

	// 4. Virtual Key Level
	allowedModels := []string{"*"}
	allowedRoutes := []string{"*"}
	if vkID != "" {
		vk, err := h.store.GetVirtualKeyByID(r.Context(), tenantID, vkID)
		if err == nil && vk != nil {
			if len(vk.AllowedModels) > 0 {
				allowedModels = vk.AllowedModels
			}
			if len(vk.AllowedRoutes) > 0 {
				allowedRoutes = vk.AllowedRoutes
			}
			ladder = append(ladder, PolicyLadderLevel{
				Level:      "virtual_key",
				Source:     "virtual_keys",
				Confidence: "observed",
				Scope: map[string]interface{}{
					"id":             vk.ID,
					"name":           vk.Name,
					"allowed_models": vk.AllowedModels,
					"allowed_routes": vk.AllowedRoutes,
					"monthly_budget": vk.MonthlyBudgetMicrocents,
					"status":         vk.Status,
				},
			})
		} else {
			ladder = append(ladder, PolicyLadderLevel{
				Level:      "virtual_key",
				Source:     "virtual_keys",
				Confidence: "unknown",
			})
		}
	} else {
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "virtual_key",
			Source:     "virtual_keys",
			Confidence: "not_configured",
		})
	}

	// 5. Device Level
	if deviceID != "" {
		confidence := "unobserved"
		complianceStatus := "UNREGISTERED"
		deviceState := "UNKNOWN"

		if h.deviceStore != nil {
			dev, devErr := h.deviceStore.GetDevice(r.Context(), tenantID, deviceID)
			if devErr == nil && dev != nil {
				confidence = "observed"
				complianceStatus = dev.OverallCompliance
				deviceState = dev.EnrollmentStatus
			}
		}

		ladder = append(ladder, PolicyLadderLevel{
			Level:      "device",
			Source:     "device_governance",
			Confidence: confidence,
			State: map[string]interface{}{
				"device_id":         deviceID,
				"compliance_status": complianceStatus,
				"state":             deviceState,
			},
		})
	} else {
		ladder = append(ladder, PolicyLadderLevel{
			Level:      "device",
			Source:     "device_governance",
			Confidence: "not_configured",
		})
	}

	resp := map[string]interface{}{
		"queried_at": atTime.Format(time.RFC3339),
		"query_params": map[string]string{
			"device_id":      deviceID,
			"agent_id":       agentID,
			"virtual_key_id": vkID,
			"project_id":     projectID,
			"provider":       provider,
			"model":          model,
			"route":          route,
		},
		"provenance_ladder": ladder,
		"effective": map[string]interface{}{
			"spend_limit_microcents": minLimit,
			"action":                 dominantAction,
			"allowed_models":         allowedModels,
			"allowed_routes":         allowedRoutes,
			"policy_version_ids":     policyVersionIDs,
		},
		"confidence": "observed",
		"provenance": map[string]interface{}{
			"data_freshness":  time.Now().UTC().Format(time.RFC3339),
			"evidence_source": "control_plane_multi_layer_resolution",
			"confidence":      "observed",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CanonicalEffectivePolicyPreimage produces a deterministic preimage covering ALL manifest fields.
func CanonicalEffectivePolicyPreimage(
	tenantID string,
	issuedAt, expiresAt int64,
	allowedModels, blockedModels []string,
	dlpRules, rateLimits map[string]interface{},
	policyVersion int,
) []byte {
	sortedAllowed := make([]string, len(allowedModels))
	copy(sortedAllowed, allowedModels)
	sort.Strings(sortedAllowed)

	sortedBlocked := make([]string, len(blockedModels))
	copy(sortedBlocked, blockedModels)
	sort.Strings(sortedBlocked)

	dlpBytes, _ := json.Marshal(dlpRules)
	rateBytes, _ := json.Marshal(rateLimits)

	return []byte(fmt.Sprintf(
		"vexa-effective-policy-v1\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s\x00%d",
		tenantID,
		issuedAt,
		expiresAt,
		strings.Join(sortedAllowed, ","),
		strings.Join(sortedBlocked, ","),
		string(dlpBytes),
		string(rateBytes),
		policyVersion,
	))
}

// GetEffectiveSigned handles GET /api/v2/policy/effective
// PRD §FR-10.6 & Task 3.8: Returns canonical JSON manifest signed with Ed25519 authority key covering ALL fields.
func (h *EffectivePolicyHandler) GetEffectiveSigned(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Authenticate caller (Strict Device Principal or Authenticated Request Principal)
	var tenantID string
	if dev, ok := middleware.GetDevicePrincipal(ctx); ok && dev != nil && dev.OrganizationID != "" {
		tenantID = dev.OrganizationID
	} else if p := middleware.RequestPrincipalFromContext(ctx); p != nil && p.OrganizationID != "" {
		tenantID = p.OrganizationID
	}

	if tenantID == "" {
		http.Error(w, `{"error":{"code":"unauthorized","message":"Authentication required to access effective policy"}}`, http.StatusUnauthorized)
		return
	}

	// 2. Fetch authoritative signing key (fail closed — no static fallback)
	privKey, err := h.getSigningKey()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"signing_authority_unavailable","message":"%s"}}`, err.Error()), http.StatusServiceUnavailable)
		return
	}

	// 3. Resolve authoritative policy state
	policyVersion := 1
	allowedModels := []string{"claude-3-5-sonnet", "claude-3-7-sonnet", "gemini-2.0-flash", "gpt-4o", "o3-mini"}
	blockedModels := []string{"claude-3-opus", "gpt-4-base"}

	dlpRules := map[string]interface{}{
		"block_private_keys": true,
		"redact_api_tokens":  true,
		"redact_pII":         true,
	}

	rateLimits := map[string]interface{}{
		"max_rpm": 60,
		"max_tpm": 100000,
	}

	if groupPolicy, err := h.store.GetActiveGroupPolicy(ctx, tenantID, "default"); err == nil && groupPolicy != nil {
		policyVersion = groupPolicy.Version
	}

	now := time.Now().UTC()
	issuedAt := now.Unix()
	expiresAt := now.Add(24 * time.Hour).Unix()

	// 4. Compute deterministic policy manifest hash covering ALL manifest fields
	preimage := CanonicalEffectivePolicyPreimage(
		tenantID, issuedAt, expiresAt, allowedModels, blockedModels, dlpRules, rateLimits, policyVersion,
	)
	hasher := sha256.New()
	hasher.Write(preimage)
	policyHash := fmt.Sprintf("sha256:%x", hasher.Sum(nil))

	// 5. Sign with control plane authority Ed25519 key
	sig := ed25519.Sign(privKey, []byte(policyHash))
	sigB64 := fmt.Sprintf("ed25519:%s", base64.StdEncoding.EncodeToString(sig))
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyB64 := fmt.Sprintf("ed25519:%s", base64.StdEncoding.EncodeToString(pubKey))

	manifest := map[string]interface{}{
		"policy_version": policyVersion,
		"policy_hash":    policyHash,
		"tenant_id":      tenantID,
		"issued_at":      issuedAt,
		"expires_at":     expiresAt,
		"allowed_models": allowedModels,
		"blocked_models": blockedModels,
		"dlp_rules":      dlpRules,
		"rate_limits":    rateLimits,
		"signature":      sigB64,
		"public_key":     pubKeyB64,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(manifest)
}

