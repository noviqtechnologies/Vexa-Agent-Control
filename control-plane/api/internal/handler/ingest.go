package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
)

type IngestHandler struct {
	store  DataStore
	broker *sse.Broker
	claims *license.Claims
}

func NewIngestHandler(s DataStore, b *sse.Broker, c *license.Claims) *IngestHandler {
	if c == nil {
		c = license.CommunityClaims()
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
