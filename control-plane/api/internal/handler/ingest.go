package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"


	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type IngestHandler struct {
	store  DataStore
	broker *sse.Broker
	claims *license.Claims
}

func NewIngestHandler(s DataStore, b *sse.Broker, c *license.Claims) *IngestHandler {
	if c == nil {
		c = license.DeveloperClaims()
	}
	return &IngestHandler{store: s, broker: b, claims: c}
}

// PostEvent handles POST /api/v1/ingest/events from the gateway.
func (h *IngestHandler) PostEvent(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var event model.RedactedEvent
	if err := dec.Decode(&event); err != nil {
		http.Error(w, `{"error":"invalid event payload"}`, http.StatusBadRequest)
		return
	}
	if !event.Valid() {
		http.Error(w, `{"error":"event failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if resolved := h.store.ResolveTenantIDForAgent(ctx, event.AgentID); resolved != "" {
		tenantID = resolved
	}

	// Seat enforcement check: reject new agent registrations if seat cap reached
	if h.claims != nil && h.claims.MaxSeats > 0 {
		exists, err := h.store.AgentExists(ctx, tenantID, event.AgentID)
		if err == nil && !exists {
			count, err := h.store.CountDistinctAgents(ctx, tenantID)
			if err == nil && count >= h.claims.MaxSeats {
				log.Printf("seat limit reached (%d/%d), rejecting new agent %s", count, h.claims.MaxSeats, event.AgentID)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":     "seat_limit_exceeded",
					"max_seats": h.claims.MaxSeats,
					"current":   count,
				})
				return
			}
		}
	}

	if err := h.store.UpsertAgent(ctx, tenantID, event.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertEvent(ctx, tenantID, &event); err != nil {
		log.Printf("insert event: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// PostAlert handles POST /api/v1/ingest/alerts from the gateway.
func (h *IngestHandler) PostAlert(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var alert model.RedactedAlert
	if err := dec.Decode(&alert); err != nil {
		http.Error(w, `{"error":"invalid alert payload"}`, http.StatusBadRequest)
		return
	}
	if !alert.Valid() {
		http.Error(w, `{"error":"alert failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if resolved := h.store.ResolveTenantIDForAgent(ctx, alert.Event.AgentID); resolved != "" {
		tenantID = resolved
	}

	if err := h.store.UpsertAgent(ctx, tenantID, alert.Event.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertEvent(ctx, tenantID, &alert.Event); err != nil {
		log.Printf("insert event for alert: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertAlert(ctx, tenantID, &alert); err != nil {
		log.Printf("insert alert: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Fan out to SSE — non-blocking, never fails the ingest.
	h.broker.PublishTenant(tenantID, alert)

	w.WriteHeader(http.StatusCreated)
}

// PostCredential handles POST /api/v1/ingest/credentials from the gateway.
func (h *IngestHandler) PostCredential(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var cred model.SanitizedCredentialMeta
	if err := dec.Decode(&cred); err != nil {
		http.Error(w, `{"error":"invalid credential payload"}`, http.StatusBadRequest)
		return
	}
	if cred.CredentialID == "" || cred.AgentID == "" {
		http.Error(w, `{"error":"credential failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if resolved := h.store.ResolveTenantIDForAgent(ctx, cred.AgentID); resolved != "" {
		tenantID = resolved
	}

	if err := h.store.UpsertAgent(ctx, tenantID, cred.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.UpsertCredential(ctx, tenantID, &cred); err != nil {
		log.Printf("upsert credential: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// PostMcpServers handles POST /api/v1/ingest/mcp-servers from the gateway.
func (h *IngestHandler) PostMcpServers(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var snap model.McpServerSnapshot
	if err := dec.Decode(&snap); err != nil {
		log.Printf("decode mcp servers payload: %v", err)
		http.Error(w, `{"error":"invalid mcp servers payload"}`, http.StatusBadRequest)
		return
	}
	if snap.AgentID == "" {
		http.Error(w, `{"error":"mcp servers snapshot missing agent_id"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if resolved := h.store.ResolveTenantIDForAgent(ctx, snap.AgentID); resolved != "" {
		tenantID = resolved
	}

	if err := h.store.UpsertAgent(ctx, tenantID, snap.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	for _, s := range snap.Servers {
		srv := s
		if err := h.store.UpsertMcpServer(ctx, tenantID, snap.AgentID, &srv); err != nil {
			log.Printf("upsert mcp server: %v", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
	}
	log.Printf("ingest mcp servers: received %d servers for agent %s in tenant %s", len(snap.Servers), snap.AgentID, tenantID)

	w.WriteHeader(http.StatusCreated)
}

// TelemetryBatchIngestPayload contains batched events from workstation SQLite WAL
type TelemetryBatchIngestPayload struct {
	DeviceID string                `json:"device_id"`
	Events   []model.RedactedEvent `json:"events"`
}

// PostTelemetryIngest handles POST /api/v2/telemetry/ingest
// Strictly enforces authenticated device identity, rejects device spoofing,
// validates batch limits, and provides truthful per-event error reporting.
func (h *IngestHandler) PostTelemetryIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Authenticate device principal
	devPrincipal, ok := middleware.GetDevicePrincipal(ctx)
	if !ok || devPrincipal == nil || devPrincipal.DeviceID == "" || devPrincipal.OrganizationID == "" {
		http.Error(w, `{"error":{"code":"unauthorized","message":"Valid workstation device authentication required"}}`, http.StatusUnauthorized)
		return
	}

	tenantID := devPrincipal.OrganizationID

	// 2. Decode payload (limit body size to 10MB)
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
	var payload TelemetryBatchIngestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":{"code":"invalid_request","message":"Malformed JSON payload or payload too large"}}`, http.StatusBadRequest)
		return
	}

	// 3. Reject device identity spoofing
	if payload.DeviceID != "" && payload.DeviceID != devPrincipal.DeviceID {
		http.Error(w, `{"error":{"code":"device_mismatch","message":"Payload device_id does not match authenticated device identity"}}`, http.StatusForbidden)
		return
	}

	// 4. Validate batch size
	if len(payload.Events) == 0 {
		http.Error(w, `{"error":{"code":"empty_batch","message":"Telemetry batch contains no events"}}`, http.StatusBadRequest)
		return
	}
	if len(payload.Events) > 1000 {
		http.Error(w, `{"error":{"code":"batch_too_large","message":"Telemetry batch exceeds maximum limit of 1000 events"}}`, http.StatusRequestEntityTooLarge)
		return
	}

	// 5. Ingest events with truthful error tracking
	acceptedCount := 0
	var insertErrors []string
	for i, ev := range payload.Events {
		eventCopy := ev
		if !eventCopy.Valid() {
			insertErrors = append(insertErrors, fmt.Sprintf("event[%d]: failed schema validation", i))
			continue
		}

		if eventCopy.AgentID == "" {
			eventCopy.AgentID = devPrincipal.DeviceID
		}

		if err := h.store.InsertEvent(ctx, tenantID, &eventCopy); err != nil {
			insertErrors = append(insertErrors, fmt.Sprintf("event[%d]: %v", i, err))
			continue
		}
		acceptedCount++
	}

	status := http.StatusCreated
	if len(insertErrors) > 0 && acceptedCount == 0 {
		status = http.StatusInternalServerError
	} else if len(insertErrors) > 0 {
		status = http.StatusMultiStatus
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"accepted_count": acceptedCount,
		"failed_count":   len(insertErrors),
		"errors":         insertErrors,
		"device_id":      devPrincipal.DeviceID,
		"tenant_id":      tenantID,
		"timestamp":      time.Now().UTC(),
	})
}

// GetAuditCheckpoints handles GET /api/v2/audit/checkpoints
// Exposes verifiable periodic signed ledger checkpoints derived from real committed ledger records.
func (h *IngestHandler) GetAuditCheckpoints(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var tenantID string

	if p, ok := middleware.GetDevicePrincipal(ctx); ok && p != nil && p.OrganizationID != "" {
		tenantID = p.OrganizationID
	} else if p := middleware.RequestPrincipalFromContext(ctx); p != nil && p.OrganizationID != "" {
		tenantID = p.OrganizationID
	}

	if tenantID == "" {
		http.Error(w, `{"error":{"code":"unauthorized","message":"Authentication required to access audit checkpoints"}}`, http.StatusUnauthorized)
		return
	}

	checkpoints, err := h.store.ListAuditCheckpoints(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":{"code":"internal_error","message":"Failed to retrieve audit checkpoints"}}`, http.StatusInternalServerError)
		return
	}
	if checkpoints == nil {
		checkpoints = []store.AuditCheckpoint{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"checkpoints": checkpoints,
		"total_count": len(checkpoints),
	})
}


// PostRequestLogs handles POST /api/v1/ingest/request-logs from the gateway.
func (h *IngestHandler) PostRequestLogs(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var logs []model.LlmRequestLog

	// 1. Attempt to decode as a single object
	var single model.LlmRequestLog
	if err := json.Unmarshal(bodyBytes, &single); err == nil && single.Valid() {
		logs = append(logs, single)
	} else {
		// 2. Attempt to decode as slice
		var list []model.LlmRequestLog
		if err := json.Unmarshal(bodyBytes, &list); err == nil {
			logs = list
		} else {
			// 3. Attempt to decode as wrapped object {"logs": [...]} or {"request_logs": [...]}
			var wrapped struct {
				Logs        []model.LlmRequestLog `json:"logs"`
				RequestLogs []model.LlmRequestLog `json:"request_logs"`
			}
			if err := json.Unmarshal(bodyBytes, &wrapped); err == nil {
				if len(wrapped.Logs) > 0 {
					logs = wrapped.Logs
				} else if len(wrapped.RequestLogs) > 0 {
					logs = wrapped.RequestLogs
				}
			}
		}
	}

	if len(logs) == 0 {
		http.Error(w, `{"error":"invalid or empty request logs payload"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(ctx)
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	var deviceID string
	if dev, ok := ctx.Value(middleware.DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.DeviceID != "" {
		deviceID = dev.DeviceID
	}

	accepted := 0
	for _, l := range logs {
		logItem := l
		if !logItem.Valid() {
			continue
		}
		if (logItem.DeviceID == nil || *logItem.DeviceID == "") && deviceID != "" {
			logItem.DeviceID = &deviceID
		}
		if err := h.store.InsertRequestLog(ctx, tenantID, &logItem); err != nil {
			log.Printf("failed to insert request log %s: %v", logItem.RequestID, err)
			continue
		}
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "accepted",
		"accepted": accepted,
		"total":    len(logs),
	})
}
