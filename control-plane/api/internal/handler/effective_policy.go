package handler

import (
	"encoding/json"
	"net/http"
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
