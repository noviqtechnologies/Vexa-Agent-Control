package handler

import (
	"encoding/json"
	"net/http"
)

// SafeModeHandler returns the static status of Safe Mode.
// Safe Mode is always active and enforced before the policy engine.
type SafeModeHandler struct{}

func NewSafeModeHandler() *SafeModeHandler {
	return &SafeModeHandler{}
}

type SafeModeStatus struct {
	Active    bool   `json:"active"`
	RuleCount int    `json:"rule_count"`
	Message   string `json:"message"`
}

func (h *SafeModeHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := SafeModeStatus{
		Active:    true,
		RuleCount: 15,
		Message:   "Safe Mode is active and enforces 15 built-in rules before the policy engine.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
