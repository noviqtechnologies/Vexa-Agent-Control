package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/sse"
)

func TestLicenseHandler_GetStatus_Community(t *testing.T) {
	ms := &mockStore{}
	h := NewLicenseHandler(ms, license.CommunityClaims())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/license/status", nil)
	rr := httptest.NewRecorder()

	h.GetStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["tier"] != "community" {
		t.Errorf("tier = %v, want community", resp["tier"])
	}
	if resp["max_seats"].(float64) != 10 {
		t.Errorf("max_seats = %v, want 10", resp["max_seats"])
	}
}

func TestIngestHandler_SeatEnforcement_RejectedWhenFull(t *testing.T) {
	ms := &mockStore{
		agentExistsFunc: func(_ context.Context, agentID string) (bool, error) {
			return false, nil // New agent
		},
		countDistinctAgentsFunc: func(_ context.Context) (int, error) {
			return 10, nil // Already at max 10 seats
		},
	}

	claims := &license.Claims{
		OrgID:    "test-org",
		Tier:     "community",
		MaxSeats: 10,
	}

	h := NewIngestHandler(ms, sse.NewBroker(), claims)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	rr := httptest.NewRecorder()

	h.PostEvent(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 Too Many Requests when seat limit reached", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["error"] != "seat_limit_exceeded" {
		t.Errorf("error = %v, want seat_limit_exceeded", resp["error"])
	}
}

func TestIngestHandler_SeatEnforcement_AllowedExistingAgent(t *testing.T) {
	ms := &mockStore{
		agentExistsFunc: func(_ context.Context, agentID string) (bool, error) {
			return true, nil // Existing agent
		},
		countDistinctAgentsFunc: func(_ context.Context) (int, error) {
			return 10, nil // At 10 seats, but existing agent should still be allowed
		},
	}

	claims := &license.Claims{
		OrgID:    "test-org",
		Tier:     "community",
		MaxSeats: 10,
	}

	h := NewIngestHandler(ms, sse.NewBroker(), claims)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	rr := httptest.NewRecorder()

	h.PostEvent(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 Created for existing agent even when seat limit is reached", rr.Code)
	}
}
