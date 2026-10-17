package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

// SupportedIdeCoverage tracks the protection state of a specific IDE target.
type SupportedIdeCoverage struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"` // "ENFORCED_ON_ROUTED_TRAFFIC" | "PARTIAL_COVERAGE" | "NOT_DETECTED"
	IsWrapped bool   `json:"is_wrapped"`
	Reason    string `json:"reason,omitempty"`
}

// WorkstationCoverageItem represents the comprehensive boundary security for a workstation.
type WorkstationCoverageItem struct {
	DeviceID          string                 `json:"device_id"`
	Hostname          string                 `json:"hostname"`
	UserIdentifier    string                 `json:"user_identifier"`
	OS                string                 `json:"os"`
	OSVersion         string                 `json:"os_version"`
	HealthState       string                 `json:"health_state"` // "HEALTHY_ENFORCED" | "STALE" | "EXPOSED" | "REVOKED"
	OverallCompliance string                 `json:"overall_compliance"`
	ManagementMode    string                 `json:"management_mode,omitempty"`
	// PostureState is the evidence-based assurance tier for this workstation.
	// Possible values:
	//   COOPERATIVE_CONFIGURED  — daemon heartbeating and PEP responding on loopback
	//   DEGRADED (OFFLINE_CACHE) — heartbeat stale (<72h), operating on last signed bundle
	//   POLICY_EXPIRED          — device offline beyond 72h policy grace window
	//   REVOKED                 — enrollment revoked; device must re-enroll
	//   EXPOSED                 — tamper detected or non-compliant configuration
	PostureState      string                 `json:"posture_state"`
	PostureEvidence   string                 `json:"posture_evidence,omitempty"`
	LastHeartbeatAt   *time.Time             `json:"last_heartbeat_at"`
	TamperCount24h    int                    `json:"tamper_count_24h"`
	ActiveIDEs        []string               `json:"active_ides"`
	IdeCoverage       []SupportedIdeCoverage `json:"ide_coverage"`
}

// CoverageHealthResponse is the authoritative fleet protection & control health envelope.
type CoverageHealthResponse struct {
	Summary struct {
		TotalWorkstations     int     `json:"total_workstations"`
		ProtectedWorkstations int     `json:"protected_workstations"` // Retained for backward compatibility
		EnforcedWorkstations  int     `json:"enforced_workstations"`
		ExposedWorkstations   int     `json:"exposed_workstations"`
		StaleWorkstations     int     `json:"stale_workstations"`
		RevokedWorkstations   int     `json:"revoked_workstations"`
		TotalActiveIDEs       int     `json:"total_active_ides"`
		TamperAlerts24h       int     `json:"tamper_alerts_24h"`
		FleetProtectionScore  float64 `json:"fleet_protection_score"`
	} `json:"summary"`
	Workstations []WorkstationCoverageItem `json:"workstations"`
	GeneratedAt  string                    `json:"generated_at"`
}

// CoverageHealthHandler exposes GET /api/v1/fleet/coverage-health
type CoverageHealthHandler struct {
	deviceStore *device.Store
}

// NewCoverageHealthHandler creates a new CoverageHealthHandler.
func NewCoverageHealthHandler(ds *device.Store) *CoverageHealthHandler {
	return &CoverageHealthHandler{deviceStore: ds}
}

// maxPolicyAgeOfflineGrace is the 72-hour window during which a device may
// operate on its local signed policy bundle without hub connectivity.
const maxPolicyAgeOfflineGrace = 72 * time.Hour

// derivePostureState maps real device signals to the canonical evidence-based
// posture vocabulary defined in enterprise-system-design.md §1.
func derivePostureState(d device.DeviceComplianceSummary, now time.Time) (state, evidence string) {
	// REVOKED — highest priority check.
	if strings.ToUpper(d.EnrollmentStatus) == "REVOKED" {
		return "REVOKED", "device enrollment revoked; must re-enroll"
	}

	// POLICY_EXPIRED — offline beyond the 72-hour grace window.
	if d.LastHeartbeatAt != nil && now.Sub(*d.LastHeartbeatAt) > maxPolicyAgeOfflineGrace {
		return "POLICY_EXPIRED",
		fmt.Sprintf("last heartbeat %.0f hours ago exceeds 72h grace window; policy bundle may be stale",
			now.Sub(*d.LastHeartbeatAt).Hours())
	}

	// DEGRADED (OFFLINE_CACHE) — stale heartbeat within grace window.
	if d.LastHeartbeatAt == nil || now.Sub(*d.LastHeartbeatAt) > 15*time.Minute {
		return "DEGRADED (OFFLINE_CACHE)", "hub connectivity lost; daemon operating on last signed policy bundle"
	}

	// EXPOSED — tamper events or non-compliant posture.
	if d.TamperCount24h > 0 || strings.ToUpper(d.OverallCompliance) == "NON_COMPLIANT" {
		return "EXPOSED",
		fmt.Sprintf("tamper_count_24h=%d compliance=%s", d.TamperCount24h, d.OverallCompliance)
	}

	// COOPERATIVE_CONFIGURED — daemon actively heartbeating, PEP configured on loopback.
	return "COOPERATIVE_CONFIGURED", "daemon heartbeating within 15 min; PEP active on 127.0.0.1:18080"
}

var canonicalIDEs = []struct {
	ID   string
	Name string
}{
	{"cursor", "Cursor"},
	{"claude", "Claude Desktop"},
	{"vscode", "VS Code"},
	{"jetbrains", "JetBrains IDEs"},
	{"windsurf", "Windsurf"},
	{"zed", "Zed Editor"},
	{"cline", "Cline"},
	{"antigravity", "Antigravity"},
	{"codex", "Codex"},
	{"opencode", "OpenCode"},
}

// GetCoverageHealth evaluates fleet workstations against active boundary controls.
func (h *CoverageHealthHandler) GetCoverageHealth(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	devicesList, err := h.deviceStore.ListDevices(r.Context(), tenantID)
	if err != nil {
		log.Printf("[CoverageHealthHandler.GetCoverageHealth] Error listing devices for tenant %s: %v", tenantID, err)
		http.Error(w, `{"error":"failed to query device coverage"}`, http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	var protectedCount, exposedCount, staleCount, revokedCount, totalIDEs, totalTamper int
	workstations := make([]WorkstationCoverageItem, 0, len(devicesList))
	seenHosts := make(map[string]int) // maps lower(hostname) -> index in workstations

	normalizeKey := func(s string) string {
		r := strings.ToLower(s)
		r = strings.ReplaceAll(r, "_", "")
		r = strings.ReplaceAll(r, "-", "")
		r = strings.ReplaceAll(r, " ", "")
		return r
	}

	for _, d := range devicesList {
		hostKey := strings.ToLower(strings.TrimSpace(d.Hostname))
		if hostKey == "" {
			hostKey = strings.ToLower(strings.TrimSpace(d.DeviceID))
		}

		// If this workstation has already been processed (e.g. re-enrolled device), merge active IDEs into existing record
		if idx, seen := seenHosts[hostKey]; seen && hostKey != "" {
			existing := &workstations[idx]
			existingActive := make(map[string]bool)
			existingNormActive := make(map[string]bool)
			for _, ide := range existing.ActiveIDEs {
				existingActive[strings.ToLower(ide)] = true
				existingNormActive[normalizeKey(ide)] = true
			}
			for _, ide := range d.ActiveIDEs {
				if !existingActive[strings.ToLower(ide)] {
					existing.ActiveIDEs = append(existing.ActiveIDEs, ide)
					existingActive[strings.ToLower(ide)] = true
					existingNormActive[normalizeKey(ide)] = true
					totalIDEs++
				}
			}
			// Refresh IDE coverage for existing workstation
			for i, c := range canonicalIDEs {
				normID := normalizeKey(c.ID)
				normName := normalizeKey(c.Name)
				if existingActive[c.ID] || existingActive[strings.ToLower(c.Name)] || existingNormActive[normID] || existingNormActive[normName] {
					existing.IdeCoverage[i].IsWrapped = true
					if c.ID == "claude" {
						existing.IdeCoverage[i].Status = "PARTIAL_COVERAGE"
						existing.IdeCoverage[i].Reason = "MCP tools wrapped; LLM completions route direct to Anthropic"
					} else {
						existing.IdeCoverage[i].Status = "ENFORCED_ON_ROUTED_TRAFFIC"
						existing.IdeCoverage[i].Reason = "Routed through local proxy"
					}
				}
			}
			continue
		}

		activeSet := make(map[string]bool)
		activeNormSet := make(map[string]bool)
		for _, ide := range d.ActiveIDEs {
			activeSet[strings.ToLower(ide)] = true
			activeNormSet[normalizeKey(ide)] = true
		}
		totalIDEs += len(d.ActiveIDEs)
		totalTamper += d.TamperCount24h

		var ideCoverage []SupportedIdeCoverage
		for _, c := range canonicalIDEs {
			normID := normalizeKey(c.ID)
			normName := normalizeKey(c.Name)
			isWrapped := activeSet[c.ID] || activeSet[strings.ToLower(c.Name)] || activeNormSet[normID] || activeNormSet[normName]
			status := "NOT_DETECTED"
			reason := "Target configuration not detected"
			if isWrapped {
				if c.ID == "claude" {
					status = "PARTIAL_COVERAGE"
					reason = "MCP tools wrapped via stdio-proxy; LLM completions route out-of-band directly to Anthropic Cloud"
				} else {
					status = "ENFORCED_ON_ROUTED_TRAFFIC"
					reason = "Target configuration wrapped and routed through local proxy"
				}
			}
			ideCoverage = append(ideCoverage, SupportedIdeCoverage{
				ID:        c.ID,
				Name:      c.Name,
				Status:    status,
				IsWrapped: isWrapped,
				Reason:    reason,
			})
		}

		// Calculate Health State
		healthState := "HEALTHY_ENFORCED"
		if strings.ToUpper(d.EnrollmentStatus) == "REVOKED" {
			healthState = "REVOKED"
			revokedCount++
		} else if d.LastHeartbeatAt == nil || now.Sub(*d.LastHeartbeatAt) > 15*time.Minute || d.OverallCompliance == "OFFLINE" {
			healthState = "STALE"
			staleCount++
		} else if d.TamperCount24h > 0 || d.OverallCompliance == "NON_COMPLIANT" {
			healthState = "EXPOSED"
			exposedCount++
		} else {
			protectedCount++
		}

		if hostKey != "" {
			seenHosts[hostKey] = len(workstations)
		}

		mgmtMode := "TEAM_MANAGED"
		if d.EnrollmentStatus == "" {
			mgmtMode = "LOCAL_DEVELOPER"
		}

		postureState, postureEvidence := derivePostureState(d, now)

		workstations = append(workstations, WorkstationCoverageItem{
			DeviceID:        d.DeviceID,
			Hostname:        d.Hostname,
			UserIdentifier:  d.UserIdentifier,
			OS:              d.OS,
			OSVersion:       d.OSVersion,
			HealthState:     healthState,
			OverallCompliance: d.OverallCompliance,
			ManagementMode:  mgmtMode,
			PostureState:    postureState,
			PostureEvidence: postureEvidence,
			LastHeartbeatAt: d.LastHeartbeatAt,
			TamperCount24h:  d.TamperCount24h,
			ActiveIDEs:      d.ActiveIDEs,
			IdeCoverage:     ideCoverage,
		})
	}

	total := len(workstations)
	score := 0.0
	if total > 0 && protectedCount > 0 {
		score = math.Round((float64(protectedCount)/float64(total))*1000) / 10
	}

	resp := CoverageHealthResponse{
		Workstations: workstations,
		GeneratedAt:  now.Format(time.RFC3339),
	}
	resp.Summary.TotalWorkstations = total
	resp.Summary.ProtectedWorkstations = protectedCount
	resp.Summary.EnforcedWorkstations = protectedCount
	resp.Summary.ExposedWorkstations = exposedCount
	resp.Summary.StaleWorkstations = staleCount
	resp.Summary.RevokedWorkstations = revokedCount
	resp.Summary.TotalActiveIDEs = totalIDEs
	resp.Summary.TamperAlerts24h = totalTamper
	resp.Summary.FleetProtectionScore = score

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
