package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

type GatewayHandler struct {
}

func NewGatewayHandler() *GatewayHandler {
	return &GatewayHandler{}
}

func (h *GatewayHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Mock implementation for Phase 1 Hub model
	b := make([]byte, 16)
	rand.Read(b)
	token := "gw_" + hex.EncodeToString(b)

	resp := map[string]interface{}{
		"token":      token,
		"status":     "registered",
		"expires_at": time.Now().Add(365 * 24 * time.Hour).Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
