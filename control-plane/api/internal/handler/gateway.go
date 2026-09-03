package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

type GatewayHandler struct {
}

func NewGatewayHandler() *GatewayHandler {
	return &GatewayHandler{}
}

func (h *GatewayHandler) Register(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := "gw_" + hex.EncodeToString(b)

	resp := map[string]interface{}{
		"organization_id": tenantID,
		"token":           token,
		"status":          "registered",
		"mode":            "edge_loopback_proxy",
		"issued_at":       time.Now().UTC().Format(time.RFC3339),
		"expires_at":      time.Now().UTC().Add(365 * 24 * time.Hour).Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Vexa-Gateway-Mode", "edge-loopback")
	_ = json.NewEncoder(w).Encode(resp)
}
