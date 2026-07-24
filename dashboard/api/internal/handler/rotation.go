package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type RotationHandler struct {
	gatewayURL       string
	policyReadSecret string
	client           *http.Client
}

func NewRotationHandler(gatewayURL, policyReadSecret string) *RotationHandler {
	return &RotationHandler{
		gatewayURL:       gatewayURL,
		policyReadSecret: policyReadSecret,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type rotationRequest struct {
	AgentID  string `json:"agent_id"`
	DrainSec int    `json:"drain_seconds,omitempty"`
}

func (h *RotationHandler) TriggerRotation(w http.ResponseWriter, r *http.Request) {
	var req rotationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.AgentID) == "" {
		http.Error(w, `{"error":"agent_id is required"}`, http.StatusUnprocessableEntity)
		return
	}

	if req.DrainSec <= 0 {
		req.DrainSec = 300
	}

	body, err := json.Marshal(req)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	gwReq, err := http.NewRequestWithContext(r.Context(), "POST", h.gatewayURL+"/api/identity/rotate", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	gwReq.Header.Set("Content-Type", "application/json")
	if h.policyReadSecret != "" {
		gwReq.Header.Set("Authorization", "Bearer "+h.policyReadSecret)
	}

	resp, err := h.client.Do(gwReq)
	if err != nil {
		http.Error(w, `{"error":"gateway unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
