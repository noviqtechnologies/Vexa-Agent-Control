package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

// ── Mock store ──────────────────────────────────────────────────────────────

var errStore = errors.New("store failure")

type mockStore struct {
	getFleetStatsFunc     func(ctx context.Context) (*store.FleetStats, error)
	listAgentsFunc        func(ctx context.Context, limit, offset int) ([]store.AgentSummary, error)
	getDecisionHeatmapFn  func(ctx context.Context, hours int) ([]store.DecisionBreakdown, error)
	listRecentEventsFunc  func(ctx context.Context, agentID string, limit int) ([]store.RecentEvent, error)
	listCredentialsFunc   func(ctx context.Context, agentID string) ([]model.SanitizedCredentialMeta, error)
	upsertAgentFunc       func(ctx context.Context, agentID string) error
	insertEventFunc       func(ctx context.Context, e *model.RedactedEvent) error
	insertAlertFunc       func(ctx context.Context, a *model.RedactedAlert) error
	upsertCredentialFunc  func(ctx context.Context, c *model.SanitizedCredentialMeta) error
	listRecentAlertsFunc  func(ctx context.Context, limit int) ([]model.RedactedAlert, error)
}

func (m *mockStore) GetFleetStats(ctx context.Context) (*store.FleetStats, error) {
	if m.getFleetStatsFunc != nil {
		return m.getFleetStatsFunc(ctx)
	}
	return &store.FleetStats{}, nil
}
func (m *mockStore) ListAgents(ctx context.Context, limit, offset int) ([]store.AgentSummary, error) {
	if m.listAgentsFunc != nil {
		return m.listAgentsFunc(ctx, limit, offset)
	}
	return nil, nil
}
func (m *mockStore) GetDecisionHeatmap(ctx context.Context, hours int) ([]store.DecisionBreakdown, error) {
	if m.getDecisionHeatmapFn != nil {
		return m.getDecisionHeatmapFn(ctx, hours)
	}
	return nil, nil
}
func (m *mockStore) ListRecentEvents(ctx context.Context, agentID string, limit int) ([]store.RecentEvent, error) {
	if m.listRecentEventsFunc != nil {
		return m.listRecentEventsFunc(ctx, agentID, limit)
	}
	return nil, nil
}
func (m *mockStore) ListCredentials(ctx context.Context, agentID string) ([]model.SanitizedCredentialMeta, error) {
	if m.listCredentialsFunc != nil {
		return m.listCredentialsFunc(ctx, agentID)
	}
	return nil, nil
}
func (m *mockStore) UpsertAgent(ctx context.Context, agentID string) error {
	if m.upsertAgentFunc != nil {
		return m.upsertAgentFunc(ctx, agentID)
	}
	return nil
}
func (m *mockStore) InsertEvent(ctx context.Context, e *model.RedactedEvent) error {
	if m.insertEventFunc != nil {
		return m.insertEventFunc(ctx, e)
	}
	return nil
}
func (m *mockStore) InsertAlert(ctx context.Context, a *model.RedactedAlert) error {
	if m.insertAlertFunc != nil {
		return m.insertAlertFunc(ctx, a)
	}
	return nil
}
func (m *mockStore) UpsertCredential(ctx context.Context, c *model.SanitizedCredentialMeta) error {
	if m.upsertCredentialFunc != nil {
		return m.upsertCredentialFunc(ctx, c)
	}
	return nil
}
func (m *mockStore) ListRecentAlerts(ctx context.Context, limit int) ([]model.RedactedAlert, error) {
	if m.listRecentAlertsFunc != nil {
		return m.listRecentAlertsFunc(ctx, limit)
	}
	return nil, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func validEventJSON() string {
	return `{
		"event_id":"evt-1","timestamp_ms":1700000000000,"session_id":"sess-1",
		"agent_id":"agent-1","tool_name":"bash","decision":"allowed",
		"dlp_findings":[],"injection_findings":[],"semantic_findings":[]
	}`
}

func validAlertJSON() string {
	return `{
		"alert_id":"alert-1","severity":"critical",
		"event":{
			"event_id":"evt-2","timestamp_ms":1700000000000,"session_id":"sess-1",
			"agent_id":"agent-1","tool_name":"bash","decision":"denied",
			"dlp_findings":[],"injection_findings":[],"semantic_findings":[]
		}
	}`
}

func validCredentialJSON() string {
	return `{
		"credential_id":"cred-1","agent_id":"agent-1",
		"scope":["read","write"],"ttl_seconds":3600,
		"created_at_ms":1700000000000,"expires_at_ms":1700003600000,
		"last_rotated_at_ms":null,"rotation_history":[]
	}`
}

// ── Fleet handler tests ─────────────────────────────────────────────────────

func TestFleetHandler_GetOverview_Success(t *testing.T) {
	ms := &mockStore{
		getFleetStatsFunc: func(_ context.Context) (*store.FleetStats, error) {
			return &store.FleetStats{TotalAgents: 5, ActiveAgents: 3, TotalEvents: 100}, nil
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/overview", nil)
	rr := httptest.NewRecorder()
	h.GetOverview(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var stats store.FleetStats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stats.TotalAgents != 5 {
		t.Errorf("TotalAgents = %d, want 5", stats.TotalAgents)
	}
}

func TestFleetHandler_GetOverview_StoreError(t *testing.T) {
	ms := &mockStore{
		getFleetStatsFunc: func(_ context.Context) (*store.FleetStats, error) {
			return nil, errStore
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/overview", nil)
	rr := httptest.NewRecorder()
	h.GetOverview(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestFleetHandler_ListAgents_EmptyResult(t *testing.T) {
	h := NewFleetHandler(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agents", nil)
	rr := httptest.NewRecorder()
	h.ListAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should return [] not null.
	body := strings.TrimSpace(rr.Body.String())
	if body != "[]" {
		t.Errorf("body = %q, want %q", body, "[]")
	}
}

func TestFleetHandler_ListAgents_Pagination(t *testing.T) {
	var capturedLimit, capturedOffset int
	ms := &mockStore{
		listAgentsFunc: func(_ context.Context, limit, offset int) ([]store.AgentSummary, error) {
			capturedLimit = limit
			capturedOffset = offset
			return nil, nil
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agents?limit=10&offset=20", nil)
	rr := httptest.NewRecorder()
	h.ListAgents(rr, req)

	if capturedLimit != 10 {
		t.Errorf("limit = %d, want 10", capturedLimit)
	}
	if capturedOffset != 20 {
		t.Errorf("offset = %d, want 20", capturedOffset)
	}
}

func TestFleetHandler_GetHeatmap_CapsAt168Hours(t *testing.T) {
	var capturedHours int
	ms := &mockStore{
		getDecisionHeatmapFn: func(_ context.Context, hours int) ([]store.DecisionBreakdown, error) {
			capturedHours = hours
			return nil, nil
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/heatmap?hours=500", nil)
	rr := httptest.NewRecorder()
	h.GetHeatmap(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if capturedHours != 168 {
		t.Errorf("hours capped = %d, want 168", capturedHours)
	}
}

func TestFleetHandler_ListEvents_WithAgentID(t *testing.T) {
	var capturedAgentID string
	ms := &mockStore{
		listRecentEventsFunc: func(_ context.Context, agentID string, _ int) ([]store.RecentEvent, error) {
			capturedAgentID = agentID
			return nil, nil
		},
	}
	h := NewFleetHandler(ms)

	r := chi.NewRouter()
	r.Get("/api/v1/fleet/agents/{agentID}/events", h.ListEvents)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agents/agent-42/events", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if capturedAgentID != "agent-42" {
		t.Errorf("agentID = %q, want %q", capturedAgentID, "agent-42")
	}
}

// ── Identity handler tests ──────────────────────────────────────────────────

func TestIdentityHandler_ListCredentials_Success(t *testing.T) {
	ms := &mockStore{
		listCredentialsFunc: func(_ context.Context, agentID string) ([]model.SanitizedCredentialMeta, error) {
			return []model.SanitizedCredentialMeta{
				{CredentialID: "cred-1", AgentID: agentID, Scope: []string{"read"}},
			}, nil
		},
	}
	h := NewIdentityHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/credentials?agent_id=agent-1", nil)
	rr := httptest.NewRecorder()
	h.ListCredentials(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var creds []model.SanitizedCredentialMeta
	if err := json.NewDecoder(rr.Body).Decode(&creds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(creds) != 1 || creds[0].CredentialID != "cred-1" {
		t.Errorf("unexpected creds: %+v", creds)
	}
}

func TestIdentityHandler_ListCredentials_StoreError(t *testing.T) {
	ms := &mockStore{
		listCredentialsFunc: func(_ context.Context, _ string) ([]model.SanitizedCredentialMeta, error) {
			return nil, errStore
		},
	}
	h := NewIdentityHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/credentials", nil)
	rr := httptest.NewRecorder()
	h.ListCredentials(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// ── Ingest handler tests ────────────────────────────────────────────────────

func TestIngestHandler_PostEvent_Success(t *testing.T) {
	var insertedEventID string
	ms := &mockStore{
		insertEventFunc: func(_ context.Context, e *model.RedactedEvent) error {
			insertedEventID = e.EventID
			return nil
		},
	}
	h := NewIngestHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if insertedEventID != "evt-1" {
		t.Errorf("insertedEventID = %q, want %q", insertedEventID, "evt-1")
	}
}

func TestIngestHandler_PostEvent_InvalidJSON(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(`{invalid`))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostEvent_UnknownFields(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	body := `{"event_id":"evt-1","session_id":"s","agent_id":"a","tool_name":"t","decision":"allowed","secret":"oops"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — unknown fields should be rejected", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostEvent_FailsValidation(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	body := `{"event_id":"evt-1","session_id":"s","agent_id":"a","tool_name":"t","decision":"invalid_decision"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnprocessableEntity)
	}
}

func TestIngestHandler_PostEvent_UpsertAgentError(t *testing.T) {
	ms := &mockStore{
		upsertAgentFunc: func(_ context.Context, _ string) error { return errStore },
	}
	h := NewIngestHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestIngestHandler_PostEvent_InsertEventError(t *testing.T) {
	ms := &mockStore{
		insertEventFunc: func(_ context.Context, _ *model.RedactedEvent) error { return errStore },
	}
	h := NewIngestHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestIngestHandler_PostAlert_Success(t *testing.T) {
	broker := sse.NewBroker()
	ch, cleanup := broker.Subscribe()
	defer cleanup()

	h := NewIngestHandler(&mockStore{}, broker)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/alerts", strings.NewReader(validAlertJSON()))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PostAlert(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	// Verify SSE fan-out.
	select {
	case msg := <-ch:
		if !strings.Contains(string(msg), "alert-1") {
			t.Errorf("SSE message missing alert ID: %s", msg)
		}
	default:
		t.Error("expected SSE message after alert ingest")
	}
}

func TestIngestHandler_PostAlert_InvalidJSON(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/alerts", strings.NewReader(`not json`))
	rr := httptest.NewRecorder()
	h.PostAlert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostAlert_FailsValidation(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	body := `{"alert_id":"","severity":"critical","event":{"event_id":"e","session_id":"s","agent_id":"a","tool_name":"t","decision":"allowed"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/alerts", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.PostAlert(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnprocessableEntity)
	}
}

func TestIngestHandler_PostCredential_Success(t *testing.T) {
	var capturedCredID string
	ms := &mockStore{
		upsertCredentialFunc: func(_ context.Context, c *model.SanitizedCredentialMeta) error {
			capturedCredID = c.CredentialID
			return nil
		},
	}
	h := NewIngestHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/credentials", strings.NewReader(validCredentialJSON()))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PostCredential(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if capturedCredID != "cred-1" {
		t.Errorf("capturedCredID = %q, want %q", capturedCredID, "cred-1")
	}
}

func TestIngestHandler_PostCredential_MissingRequiredFields(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker())

	tests := []struct {
		name string
		body string
	}{
		{"missing_credential_id", `{"credential_id":"","agent_id":"a"}`},
		{"missing_agent_id", `{"credential_id":"c","agent_id":""}`},
		{"both_empty", `{"credential_id":"","agent_id":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/credentials", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.PostCredential(rr, req)

			if rr.Code != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusUnprocessableEntity)
			}
		})
	}
}

// ── Alert handler tests ─────────────────────────────────────────────────────

func TestAlertHandler_ListRecent_Success(t *testing.T) {
	ms := &mockStore{
		listRecentAlertsFunc: func(_ context.Context, limit int) ([]model.RedactedAlert, error) {
			return []model.RedactedAlert{
				{AlertID: "alert-1", Severity: "critical"},
			}, nil
		},
	}
	h := NewAlertHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/recent?limit=10", nil)
	rr := httptest.NewRecorder()
	h.ListRecent(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var alerts []model.RedactedAlert
	if err := json.NewDecoder(rr.Body).Decode(&alerts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("got %d alerts, want 1", len(alerts))
	}
}

func TestAlertHandler_ListRecent_StoreError(t *testing.T) {
	ms := &mockStore{
		listRecentAlertsFunc: func(_ context.Context, _ int) ([]model.RedactedAlert, error) {
			return nil, errStore
		},
	}
	h := NewAlertHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/recent", nil)
	rr := httptest.NewRecorder()
	h.ListRecent(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// ── queryInt tests ──────────────────────────────────────────────────────────

func TestQueryInt(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		key      string
		fallback int
		want     int
	}{
		{"present", "limit=10", "limit", 50, 10},
		{"missing", "", "limit", 50, 50},
		{"negative", "limit=-1", "limit", 50, 50},
		{"non_numeric", "limit=abc", "limit", 50, 50},
		{"zero", "limit=0", "limit", 50, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			got := queryInt(req, tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("queryInt() = %d, want %d", got, tt.want)
			}
		})
	}
}
