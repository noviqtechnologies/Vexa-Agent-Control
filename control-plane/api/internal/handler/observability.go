package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)


// ObservabilityHandler handles unified Request Logs, Audit Logs, and Deleted Entities.
type ObservabilityHandler struct {
	spendStore *spend.Store
	store      *store.Store
}

// NewObservabilityHandler creates a new ObservabilityHandler.
func NewObservabilityHandler(ss *spend.Store, st *store.Store) *ObservabilityHandler {
	return &ObservabilityHandler{
		spendStore: ss,
		store:      st,
	}
}

// ListRequestLogs handles GET /api/v1/observability/request-logs
func (h *ObservabilityHandler) ListRequestLogs(w http.ResponseWriter, r *http.Request) {
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
	offset := queryInt(r, "offset", 0)

	q := spend.RunQuery{
		Limit:          limit,
		Offset:         offset,
		Since:          time.Now().UTC().Add(-time.Duration(hours) * time.Hour),
		DeviceID:       r.URL.Query().Get("device_id"),
		Provider:       r.URL.Query().Get("provider"),
		Model:          r.URL.Query().Get("model"),
		State:          r.URL.Query().Get("status"),
		RequestID:      r.URL.Query().Get("request_id"),
		SessionID:      r.URL.Query().Get("session_id"),
		VirtualKeyHash: r.URL.Query().Get("key_hash"),
		VirtualKeyID:   r.URL.Query().Get("virtual_key_id"),
		User:           r.URL.Query().Get("user"),
		Search:         r.URL.Query().Get("search"),
	}

	if q.State == "" {
		q.State = r.URL.Query().Get("state")
	}

	var runs []spend.RunSummary
	var err error
	if h.spendStore != nil {
		runs, err = h.spendStore.ListRuns(r.Context(), tenantID, q)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list request logs: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []spend.RunSummary{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": tenantID,
		"request_logs":    runs,
		"total":           len(runs),
		"data_freshness":  time.Now().UTC().Format(time.RFC3339),
		"confidence":      "observed",
	})
}

// StreamRequestLogs handles GET /api/v1/observability/request-logs/stream (SSE Live Tail)
func (h *ObservabilityHandler) StreamRequestLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send initial ping
	fmt.Fprintf(w, "event: ready\ndata: {\"status\":\"connected\",\"tenant_id\":%q}\n\n", tenantID)
	flusher.Flush()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	lastSince := time.Now().UTC().Add(-10 * time.Second)

	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-ticker.C:
			if h.spendStore != nil {
				q := spend.RunQuery{
					Limit: 10,
					Since: lastSince,
				}
				runs, err := h.spendStore.ListRuns(r.Context(), tenantID, q)
				if err == nil && len(runs) > 0 {
					data, _ := json.Marshal(runs)
					fmt.Fprintf(w, "event: logs\ndata: %s\n\n", string(data))
					flusher.Flush()
					lastSince = t
				} else {
					// Heartbeat keepalive
					fmt.Fprintf(w, "event: ping\ndata: {\"time\":%d}\n\n", t.Unix())
					flusher.Flush()
				}
			}
		}
	}
}

// ListAuditLogs handles GET /api/v1/observability/audit-logs or GET /api/v1/audit/logs
func (h *ObservabilityHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	filter := store.AuditLogFilter{
		Limit:     limit,
		Offset:    offset,
		ObjectID:  r.URL.Query().Get("object_id"),
		TableName: r.URL.Query().Get("table_name"),
		Action:    r.URL.Query().Get("action"),
		ChangedBy: r.URL.Query().Get("changed_by"),
	}

	var events []store.AuditEvent
	var total int
	var err error
	if h.store != nil {
		events, total, err = h.store.ListAuditLogs(r.Context(), tenantID, filter)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list audit logs: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": tenantID,
		"audit_logs":      events,
		"total":           total,
		"page":            (offset / limit) + 1,
		"limit":           limit,
	})
}

// ListDeletedKeys handles GET /api/v1/observability/deleted-keys
func (h *ObservabilityHandler) ListDeletedKeys(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	var keys []store.VirtualKey
	var err error
	if h.store != nil {
		keys, err = h.store.ListDeletedVirtualKeys(r.Context(), tenantID, limit, offset)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list deleted keys: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []store.VirtualKey{}
	}


	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id":      tenantID,
		"deleted_virtual_keys": keys,
		"total":                len(keys),
	})
}

// ListDeletedTeams handles GET /api/v1/observability/deleted-teams
func (h *ObservabilityHandler) ListDeletedTeams(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": tenantID,
		"deleted_teams":   []map[string]interface{}{},
		"total":           0,
	})
}

