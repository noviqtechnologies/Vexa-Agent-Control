package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

// RunHandler exposes broker LLM run inspection and forensic dossiers.
type RunHandler struct {
	spendStore  *spend.Store
	store       DataStore
	deviceStore *device.Store
}

// NewRunHandler creates a new RunHandler.
func NewRunHandler(ss *spend.Store, ds DataStore, devStores ...*device.Store) *RunHandler {
	var devStore *device.Store
	if len(devStores) > 0 {
		devStore = devStores[0]
	}
	return &RunHandler{
		spendStore:  ss,
		store:       ds,
		deviceStore: devStore,
	}
}

// ListRuns handles GET /api/v1/runs
func (h *RunHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	hours := queryInt(r, "hours", 24)
	if hours <= 0 || hours > 720 {
		hours = 24
	}

	limit := queryInt(r, "limit", 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := spend.RunQuery{
		Limit:    limit,
		Since:    time.Now().UTC().Add(-time.Duration(hours) * time.Hour),
		DeviceID: r.URL.Query().Get("device_id"),
		Provider: r.URL.Query().Get("provider"),
		Model:    r.URL.Query().Get("model"),
		State:    r.URL.Query().Get("state"),
	}

	runs, err := h.spendStore.ListRuns(r.Context(), tenantID, q)
	if err != nil {
		http.Error(w, `{"error":"failed to list runs"}`, http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []spend.RunSummary{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": tenantID,
		"runs":            runs,
		"data_freshness":  time.Now().UTC().Format(time.RFC3339),
		"confidence":      "observed",
	})
}

// GetRun handles GET /api/v1/runs/{run_id}
func (h *RunHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	runID := chi.URLParam(r, "run_id")
	if runID == "" {
		http.Error(w, `{"error":"missing run_id"}`, http.StatusBadRequest)
		return
	}

	dossier, err := h.spendStore.GetRunDossier(r.Context(), tenantID, runID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"not_found","message":"run not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"failed to fetch run dossier"}`, http.StatusInternalServerError)
		return
	}

	// Parse JSON policy snapshot if available
	var parsedPolicy interface{}
	if dossier.PolicySnapshot != "" {
		_ = json.Unmarshal([]byte(dossier.PolicySnapshot), &parsedPolicy)
	}
	if parsedPolicy == nil {
		parsedPolicy = map[string]interface{}{}
	}

	netBilledMicrocents := int64(0)
	if strings.ToUpper(dossier.State) == "SETTLED" {
		netBilledMicrocents = int64(dossier.SettledMicrocents)
	}

	// Resolve true device identity and compliance
	deviceCompliance := "NOT_ENROLLED"
	deviceHostname := dossier.DeviceID
	confidence := "observed"

	if h.deviceStore != nil && dossier.DeviceID != "" {
		dev, devErr := h.deviceStore.GetDevice(r.Context(), tenantID, dossier.DeviceID)
		if devErr == nil && dev != nil {
			deviceCompliance = dev.OverallCompliance
			if dev.Hostname != "" {
				deviceHostname = dev.Hostname
			}
		} else {
			deviceCompliance = "UNREGISTERED"
			confidence = "inferred"
		}
	} else if dossier.DeviceID == "" {
		deviceCompliance = "UNSPECIFIED"
		confidence = "inferred"
	}

	resp := map[string]interface{}{
		"run_id":     dossier.RunID,
		"request_id": dossier.RequestID,
		"identity": map[string]interface{}{
			"device_id":          dossier.DeviceID,
			"device_hostname":    deviceHostname,
			"device_compliance":  deviceCompliance,
			"project_id":         dossier.ProjectID,
			"virtual_key_id":     dossier.VirtualKeyID,
			"virtual_key_prefix": dossier.VirtualKeyPrefix,
			"virtual_key_alias":  dossier.VirtualKeyAlias,
			"session_id":         dossier.SessionID,
			"internal_user_id":   dossier.InternalUserID,
			"end_user_id":        dossier.EndUserID,
		},
		"policy": map[string]interface{}{
			"snapshot":               parsedPolicy,
			"price_book_version_id": dossier.PriceBookVersionID,
		},
		"dispatch": map[string]interface{}{
			"provider": dossier.Provider,
			"model":    dossier.Model,
		},
		"economics": map[string]interface{}{
			"reserved_microcents":   dossier.ReservedMicrocents,
			"settled_microcents":    dossier.SettledMicrocents,
			"released_microcents":   dossier.ReleasedMicrocents,
			"net_billed_microcents": netBilledMicrocents,
			"currency":              "USD",
			"input_tokens":          dossier.InputTokens,
			"output_tokens":         dossier.OutputTokens,
			"cached_tokens":         dossier.CachedTokens,
			"total_tokens":          dossier.TotalTokens,
			"ttft_ms":               dossier.TTFTMs,
			"events":                dossier.Events,
		},
		"outcome": map[string]interface{}{
			"state":          dossier.State,
			"status_code":    dossier.StatusCode,
			"started_at":     dossier.StartedAt.Format(time.RFC3339),
			"settled_at":     dossier.SettledAt,
			"released_at":    dossier.ReleasedAt,
			"release_reason": dossier.ReleaseReason,
			"duration_ms":    dossier.DurationMs,
		},
		"provenance": map[string]interface{}{
			"data_freshness":  time.Now().UTC().Format(time.RFC3339),
			"evidence_source": "postgresql_spend_reservations",
			"confidence":      confidence,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
