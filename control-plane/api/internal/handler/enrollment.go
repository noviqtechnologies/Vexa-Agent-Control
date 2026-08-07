package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type EnrollmentHandler struct {
	store     *store.Store
	jwtSecret []byte
}

func NewEnrollmentHandler(s *store.Store, jwtSecret string) *EnrollmentHandler {
	if jwtSecret == "" {
		jwtSecret = "local-dev-device-jwt-secret-change-me"
	}
	return &EnrollmentHandler{
		store:     s,
		jwtSecret: []byte(jwtSecret),
	}
}

type EnrollRequest struct {
	EnrollmentToken  string `json:"enrollment_token"`
	DeviceID         string `json:"device_id"`
	Hostname         string `json:"hostname"`
	OSArch           string `json:"os_arch"`
	OSFamily         string `json:"os_family"`
	PublicKey        string `json:"public_key"`
	AgentWallVersion string `json:"agentwall_version"`
}

type EnrollResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// POST /api/v1/enroll
func (h *EnrollmentHandler) PostEnroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"INVALID_JSON","message":"invalid json payload"}}`, http.StatusBadRequest)
		return
	}

	if req.EnrollmentToken == "" || req.DeviceID == "" || req.PublicKey == "" {
		http.Error(w, `{"error":{"code":"INVALID_REQUEST","message":"enrollment_token, device_id, and public_key are required"}}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	if err := h.store.ConsumeEnrollmentToken(ctx, req.EnrollmentToken); err != nil {
		log.Printf("consume enrollment token failed: %v", err)
		http.Error(w, `{"error":{"code":"TOKEN_INVALID","message":"invalid or expired enrollment token"}}`, http.StatusUnauthorized)
		return
	}

	if req.OSFamily == "" {
		req.OSFamily = "unknown"
	}
	if req.OSArch == "" {
		req.OSArch = "unknown"
	}
	if req.AgentWallVersion == "" {
		req.AgentWallVersion = "1.0.23"
	}

	dev := model.Device{
		DeviceID:          req.DeviceID,
		Hostname:          req.Hostname,
		OSArch:            req.OSArch,
		OSFamily:          req.OSFamily,
		PublicKey:         req.PublicKey,
		AgentWallVersion:  req.AgentWallVersion,
		MCPServersTotal:   0,
		MCPServersWrapped: 0,
	}

	if err := h.store.RegisterDevice(ctx, &dev); err != nil {
		log.Printf("register device failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to register device"}}`, http.StatusInternalServerError)
		return
	}

	// Issue short-lived Device JWT valid for 30 days
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	claims := jwt.MapClaims{
		"sub":       req.DeviceID,
		"device_id": req.DeviceID,
		"os_family": req.OSFamily,
		"exp":       expiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"iss":       "agentwall-hub",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(h.jwtSecret)
	if err != nil {
		log.Printf("sign device token failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to sign device token"}}`, http.StatusInternalServerError)
		return
	}

	resp := EnrollResponse{
		DeviceID:    req.DeviceID,
		DeviceToken: tokenString,
		ExpiresAtMs: expiresAt.UnixMilli(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

type CreateTokenRequest struct {
	TokenID    string `json:"token_id"`
	RawToken   string `json:"raw_token"`
	CreatedBy  string `json:"created_by"`
	MaxUses    int    `json:"max_uses"`
	TTLHours   int    `json:"ttl_hours"`
}

// POST /api/v1/admin/enrollment-tokens
func (h *EnrollmentHandler) PostCreateToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"INVALID_JSON","message":"invalid json payload"}}`, http.StatusBadRequest)
		return
	}

	if req.RawToken == "" {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to generate secure token"}}`, http.StatusInternalServerError)
			return
		}
		req.RawToken = "TOK-" + strings.ToUpper(hex.EncodeToString(bytes))
	}
	if req.TokenID == "" {
		req.TokenID = "tok-" + time.Now().Format("20060102150405")
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "admin@corp.com"
	}

	tok, err := h.store.CreateEnrollmentToken(r.Context(), req.TokenID, req.RawToken, req.CreatedBy, req.MaxUses, req.TTLHours)
	if err != nil {
		log.Printf("create token failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to create enrollment token"}}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tok)
}
