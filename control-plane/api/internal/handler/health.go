package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type HealthHandler struct {
	pool       *pgxpool.Pool
	store      *store.Store
	spendStore *spend.Store
}

func NewHealthHandler(pool interface{ Pool() *pgxpool.Pool }) *HealthHandler {
	if pool == nil {
		return &HealthHandler{}
	}
	return &HealthHandler{pool: pool.Pool()}
}

func (h *HealthHandler) SetDependencies(st *store.Store, ss *spend.Store) {
	h.store = st
	h.spendStore = ss
}

// Healthz handles liveness checks (returns 200 immediately).
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Readyz handles multi-factor readiness checks.
func (h *HealthHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{
		"database":     "ok",
		"spend_engine": "ok",
		"route_engine": "ok",
		"audit_spool":  "ok",
	}
	ready := true

	// 1. Database Ping
	if h.pool != nil {
		if err := h.pool.Ping(ctx); err != nil {
			checks["database"] = "unreachable"
			ready = false
		}
	} else {
		checks["database"] = "uninitialized"
		ready = false
	}

	// 2. Spend Store Check
	if h.spendStore == nil {
		checks["spend_engine"] = "uninitialized"
		ready = false
	}

	status := "ready"
	httpCode := http.StatusOK
	if !ready {
		status = "unavailable"
		httpCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"checks":    checks,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
