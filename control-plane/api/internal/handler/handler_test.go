package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// ── Mock store ──────────────────────────────────────────────────────────────

var errStore = errors.New("store failure")

type mockStore struct {
	getFleetStatsFunc     func(ctx context.Context, tenantID string, hours int) (*store.FleetStats, error)
	listAgentsFunc        func(ctx context.Context, tenantID string, limit, offset int, hours int) ([]store.AgentSummary, error)
	getDecisionHeatmapFn  func(ctx context.Context, tenantID string, hours int) ([]store.DecisionBreakdown, error)
	listRecentEventsFunc  func(ctx context.Context, tenantID, agentID string, limit int) ([]store.RecentEvent, error)
	listCredentialsFunc   func(ctx context.Context, tenantID, agentID string) ([]model.SanitizedCredentialMeta, error)
	upsertAgentFunc       func(ctx context.Context, tenantID, agentID string) error
	insertEventFunc       func(ctx context.Context, tenantID string, e *model.RedactedEvent) error
	insertAlertFunc       func(ctx context.Context, tenantID string, a *model.RedactedAlert) error
	upsertCredentialFunc  func(ctx context.Context, tenantID string, c *model.SanitizedCredentialMeta) error
	listRecentAlertsFunc  func(ctx context.Context, tenantID string, limit int, hours int) ([]model.RedactedAlert, error)
	getThreatSummaryFunc    func(ctx context.Context, tenantID string, hours int) (*store.ThreatSummary, error)
	getThreatTimelineFunc   func(ctx context.Context, tenantID string, hours int) ([]store.ThreatTimelinePoint, error)
	getTopThreatPatternsFunc func(ctx context.Context, tenantID string, hours int, limit int) ([]store.ThreatPattern, error)
	countDistinctAgentsFunc  func(ctx context.Context, tenantID string) (int, error)
	agentExistsFunc          func(ctx context.Context, tenantID, agentID string) (bool, error)
	getProviderKeyByProviderFunc func(ctx context.Context, tenantID, provider string) (*store.ProviderKey, error)
}

func (m *mockStore) GetFleetStats(ctx context.Context, tenantID string, hours int) (*store.FleetStats, error) {
	if m.getFleetStatsFunc != nil {
		return m.getFleetStatsFunc(ctx, tenantID, hours)
	}
	return &store.FleetStats{}, nil
}
func (m *mockStore) ListAgents(ctx context.Context, tenantID string, limit, offset int, hours int) ([]store.AgentSummary, error) {
	if m.listAgentsFunc != nil {
		return m.listAgentsFunc(ctx, tenantID, limit, offset, hours)
	}
	return nil, nil
}
func (m *mockStore) GetDecisionHeatmap(ctx context.Context, tenantID string, hours int) ([]store.DecisionBreakdown, error) {
	if m.getDecisionHeatmapFn != nil {
		return m.getDecisionHeatmapFn(ctx, tenantID, hours)
	}
	return nil, nil
}
func (m *mockStore) ListRecentEvents(ctx context.Context, tenantID, agentID string, limit int) ([]store.RecentEvent, error) {
	if m.listRecentEventsFunc != nil {
		return m.listRecentEventsFunc(ctx, tenantID, agentID, limit)
	}
	return nil, nil
}
func (m *mockStore) ListCredentials(ctx context.Context, tenantID, agentID string) ([]model.SanitizedCredentialMeta, error) {
	if m.listCredentialsFunc != nil {
		return m.listCredentialsFunc(ctx, tenantID, agentID)
	}
	return nil, nil
}
func (m *mockStore) UpsertAgent(ctx context.Context, tenantID, agentID string) error {
	if m.upsertAgentFunc != nil {
		return m.upsertAgentFunc(ctx, tenantID, agentID)
	}
	return nil
}
func (m *mockStore) CountDistinctAgents(ctx context.Context, tenantID string) (int, error) {
	if m.countDistinctAgentsFunc != nil {
		return m.countDistinctAgentsFunc(ctx, tenantID)
	}
	return 0, nil
}
func (m *mockStore) AgentExists(ctx context.Context, tenantID, agentID string) (bool, error) {
	if m.agentExistsFunc != nil {
		return m.agentExistsFunc(ctx, tenantID, agentID)
	}
	return false, nil
}
func (m *mockStore) ResolveTenantIDForAgent(ctx context.Context, agentID string) string {
	return "00000000-0000-0000-0000-000000000001"
}
func (m *mockStore) InsertEvent(ctx context.Context, tenantID string, e *model.RedactedEvent) error {
	if m.insertEventFunc != nil {
		return m.insertEventFunc(ctx, tenantID, e)
	}
	return nil
}
func (m *mockStore) InsertAlert(ctx context.Context, tenantID string, a *model.RedactedAlert) error {
	if m.insertAlertFunc != nil {
		return m.insertAlertFunc(ctx, tenantID, a)
	}
	return nil
}
func (m *mockStore) UpsertCredential(ctx context.Context, tenantID string, c *model.SanitizedCredentialMeta) error {
	if m.upsertCredentialFunc != nil {
		return m.upsertCredentialFunc(ctx, tenantID, c)
	}
	return nil
}
func (m *mockStore) ListRecentAlerts(ctx context.Context, tenantID string, limit int, hours int) ([]model.RedactedAlert, error) {
	if m.listRecentAlertsFunc != nil {
		return m.listRecentAlertsFunc(ctx, tenantID, limit, hours)
	}
	return nil, nil
}

func (m *mockStore) GetThreatSummary(ctx context.Context, tenantID string, hours int) (*store.ThreatSummary, error) {
	if m.getThreatSummaryFunc != nil {
		return m.getThreatSummaryFunc(ctx, tenantID, hours)
	}
	return &store.ThreatSummary{}, nil
}

func (m *mockStore) GetThreatTimeline(ctx context.Context, tenantID string, hours int) ([]store.ThreatTimelinePoint, error) {
	if m.getThreatTimelineFunc != nil {
		return m.getThreatTimelineFunc(ctx, tenantID, hours)
	}
	return nil, nil
}

func (m *mockStore) GetTopThreatPatterns(ctx context.Context, tenantID string, hours int, limit int) ([]store.ThreatPattern, error) {
	if m.getTopThreatPatternsFunc != nil {
		return m.getTopThreatPatternsFunc(ctx, tenantID, hours, limit)
	}
	return nil, nil
}

func (m *mockStore) UpsertMcpServer(ctx context.Context, tenantID, agentID string, s *model.SanitizedMcpServerMeta) error {
	return nil
}
func (m *mockStore) ListMcpServersByAgent(ctx context.Context, tenantID, agentID string) ([]store.McpServerInventoryRow, error) {
	return nil, nil
}
func (m *mockStore) ListMcpServersFleetWide(ctx context.Context, tenantID string) ([]store.McpServerInventoryRow, error) {
	return nil, nil
}

func (m *mockStore) UpsertSpendBudget(ctx context.Context, tenantID string, b *store.SpendBudget) error {
	return nil
}
func (m *mockStore) ListSpendBudgets(ctx context.Context, tenantID string) ([]store.SpendBudget, error) {
	return nil, nil
}
func (m *mockStore) UpsertSpendSnapshot(ctx context.Context, tenantID string, snap *store.SpendSnapshot) error {
	return nil
}
func (m *mockStore) ListSpendSnapshots(ctx context.Context, tenantID string) ([]store.SpendSnapshot, error) {
	return nil, nil
}
func (m *mockStore) InsertIncreaseRequest(ctx context.Context, tenantID string, r *store.IncreaseRequest) error {
	return nil
}
func (m *mockStore) ResolveIncreaseRequest(ctx context.Context, tenantID, id string, status string, resolvedBy string, newCap *int64) error {
	return nil
}
func (m *mockStore) ListIncreaseRequests(ctx context.Context, tenantID string) ([]store.IncreaseRequest, error) {
	return nil, nil
}

func (m *mockStore) GetActiveGroupPolicy(ctx context.Context, tenantID, groupID string) (*store.GroupPolicyVersion, error) {
	return nil, nil
}
func (m *mockStore) PublishGroupPolicy(ctx context.Context, tenantID, groupID string, claims json.RawMessage, tools json.RawMessage, createdBy string) (*store.GroupPolicyVersion, error) {
	return nil, nil
}
func (m *mockStore) ListGroupPolicies(ctx context.Context, tenantID string) ([]*store.GroupPolicyVersion, error) {
	return nil, nil
}

func (m *mockStore) InsertProviderKey(ctx context.Context, tenantID string, k *store.ProviderKey) error {
	return nil
}
func (m *mockStore) ListProviderKeys(ctx context.Context, tenantID string) ([]store.ProviderKey, error) {
	return nil, nil
}
func (m *mockStore) DeleteProviderKey(ctx context.Context, tenantID, id string) error {
	return nil
}
func (m *mockStore) GetProviderKeyByProvider(ctx context.Context, tenantID, provider string) (*store.ProviderKey, error) {
	if m.getProviderKeyByProviderFunc != nil {
		return m.getProviderKeyByProviderFunc(ctx, tenantID, provider)
	}
	return nil, nil
}

// Pillar 1: Scoped Virtual Keys (stub implementations)
func (m *mockStore) CreateVirtualKey(ctx context.Context, tenantID string, k *store.VirtualKey) error {
	return nil
}
func (m *mockStore) ListVirtualKeys(ctx context.Context, tenantID string) ([]store.VirtualKey, error) {
	return nil, nil
}
func (m *mockStore) GetVirtualKeyByID(ctx context.Context, tenantID, id string) (*store.VirtualKey, error) {
	return nil, store.ErrVirtualKeyNotFound
}
func (m *mockStore) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*store.VirtualKey, error) {
	return nil, store.ErrVirtualKeyNotFound
}
func (m *mockStore) RotateVirtualKey(ctx context.Context, tenantID, id string, newKeyHash, newKeyPrefix string, gracePeriod time.Duration) (*store.VirtualKey, error) {
	return nil, store.ErrVirtualKeyNotFound
}
func (m *mockStore) DeleteVirtualKey(ctx context.Context, tenantID, id string) error {
	return nil
}
func (m *mockStore) IncrementVirtualKeySpend(ctx context.Context, tenantID, id string, deltaMicrocents int64) (int64, error) {
	return 0, nil
}
func (m *mockStore) ResetVirtualKeySpend(ctx context.Context, tenantID, id string) error {
	return nil
}

// Central Provider Key Vault stubs
func (m *mockStore) InsertEncryptedProviderKey(ctx context.Context, tenantID, provider, keyAlias, plainSecret string, kmsProvider kms.KMSProvider) error {
	return nil
}
func (m *mockStore) GetDecryptedProviderKey(ctx context.Context, tenantID, provider string, kmsProvider kms.KMSProvider) (string, error) {
	return "", store.ErrProviderKeyNotFound
}
func (m *mockStore) ListEncryptedProviderKeys(ctx context.Context, tenantID string) ([]store.ProviderKeyMeta, error) {
	return nil, nil
}
func (m *mockStore) DeleteEncryptedProviderKey(ctx context.Context, tenantID, provider string) error {
	return nil
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
	var capturedHours int
	ms := &mockStore{
		getFleetStatsFunc: func(_ context.Context, _ string, hours int) (*store.FleetStats, error) {
			capturedHours = hours
			return &store.FleetStats{TotalAgents: 5, ActiveAgents: 3, TotalEvents: 100}, nil
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/overview?hours=48", nil)
	rr := httptest.NewRecorder()
	h.GetOverview(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if capturedHours != 48 {
		t.Errorf("hours = %d, want 48", capturedHours)
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
		getFleetStatsFunc: func(_ context.Context, _ string, _ int) (*store.FleetStats, error) {
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
	var capturedLimit, capturedOffset, capturedHours int
	ms := &mockStore{
		listAgentsFunc: func(_ context.Context, _ string, limit, offset int, hours int) ([]store.AgentSummary, error) {
			capturedLimit = limit
			capturedOffset = offset
			capturedHours = hours
			return nil, nil
		},
	}
	h := NewFleetHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agents?limit=10&offset=20&hours=72", nil)
	rr := httptest.NewRecorder()
	h.ListAgents(rr, req)

	if capturedLimit != 10 {
		t.Errorf("limit = %d, want 10", capturedLimit)
	}
	if capturedOffset != 20 {
		t.Errorf("offset = %d, want 20", capturedOffset)
	}
	if capturedHours != 72 {
		t.Errorf("hours = %d, want 72", capturedHours)
	}
}

func TestFleetHandler_GetHeatmap_CapsAt168Hours(t *testing.T) {
	var capturedHours int
	ms := &mockStore{
		getDecisionHeatmapFn: func(_ context.Context, _ string, hours int) ([]store.DecisionBreakdown, error) {
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
		listRecentEventsFunc: func(_ context.Context, _ string, agentID string, _ int) ([]store.RecentEvent, error) {
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
		listCredentialsFunc: func(_ context.Context, _ string, agentID string) ([]model.SanitizedCredentialMeta, error) {
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
		listCredentialsFunc: func(_ context.Context, _ string, _ string) ([]model.SanitizedCredentialMeta, error) {
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
		insertEventFunc: func(_ context.Context, _ string, e *model.RedactedEvent) error {
			insertedEventID = e.EventID
			return nil
		},
	}
	h := NewIngestHandler(ms, sse.NewBroker(), nil)

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
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(`{invalid`))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostEvent_UnknownFields(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

	body := `{"event_id":"evt-1","session_id":"s","agent_id":"a","tool_name":"t","decision":"allowed","secret":"oops"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — unknown fields should be rejected", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostEvent_FailsValidation(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

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
		upsertAgentFunc: func(_ context.Context, _ string, _ string) error { return errStore },
	}
	h := NewIngestHandler(ms, sse.NewBroker(), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(validEventJSON()))
	rr := httptest.NewRecorder()
	h.PostEvent(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestIngestHandler_PostEvent_InsertEventError(t *testing.T) {
	ms := &mockStore{
		insertEventFunc: func(_ context.Context, _ string, _ *model.RedactedEvent) error { return errStore },
	}
	h := NewIngestHandler(ms, sse.NewBroker(), nil)

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

	h := NewIngestHandler(&mockStore{}, broker, nil)

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
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/alerts", strings.NewReader(`not json`))
	rr := httptest.NewRecorder()
	h.PostAlert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestIngestHandler_PostAlert_FailsValidation(t *testing.T) {
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

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
		upsertCredentialFunc: func(_ context.Context, _ string, c *model.SanitizedCredentialMeta) error {
			capturedCredID = c.CredentialID
			return nil
		},
	}
	h := NewIngestHandler(ms, sse.NewBroker(), nil)

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
	h := NewIngestHandler(&mockStore{}, sse.NewBroker(), nil)

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
	var capturedHours int
	ms := &mockStore{
		listRecentAlertsFunc: func(_ context.Context, _ string, limit int, hours int) ([]model.RedactedAlert, error) {
			capturedHours = hours
			return []model.RedactedAlert{
				{AlertID: "alert-1", Severity: "critical"},
			}, nil
		},
	}
	h := NewAlertHandler(ms, sse.NewBroker())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/recent?limit=10&hours=48", nil)
	rr := httptest.NewRecorder()
	h.ListRecent(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if capturedHours != 48 {
		t.Errorf("hours = %d, want 48", capturedHours)
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
		listRecentAlertsFunc: func(_ context.Context, _ string, _ int, _ int) ([]model.RedactedAlert, error) {
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

// ── Threat handler tests ──────────────────────────────────────────────────

func TestThreatHandler_GetSummary_Success(t *testing.T) {
	ms := &mockStore{
		getThreatSummaryFunc: func(_ context.Context, _ string, hours int) (*store.ThreatSummary, error) {
			return &store.ThreatSummary{
				DlpTotal:       10,
				InjectionTotal: 5,
				SemanticTotal:  3,
				EventsWithDlp:  8,
				EventsWithInj:  4,
				EventsWithSem:  2,
			}, nil
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/summary?hours=48", nil)
	rr := httptest.NewRecorder()
	h.GetSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var s store.ThreatSummary
	if err := json.NewDecoder(rr.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.DlpTotal != 10 {
		t.Errorf("dlp_total = %d, want 10", s.DlpTotal)
	}
}

func TestThreatHandler_GetSummary_StoreError(t *testing.T) {
	ms := &mockStore{
		getThreatSummaryFunc: func(_ context.Context, _ string, _ int) (*store.ThreatSummary, error) {
			return nil, errStore
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/summary", nil)
	rr := httptest.NewRecorder()
	h.GetSummary(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestThreatHandler_GetSummary_ClampHours(t *testing.T) {
	var capturedHours int
	ms := &mockStore{
		getThreatSummaryFunc: func(_ context.Context, _ string, hours int) (*store.ThreatSummary, error) {
			capturedHours = hours
			return &store.ThreatSummary{}, nil
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/summary?hours=9999", nil)
	rr := httptest.NewRecorder()
	h.GetSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if capturedHours != 720 {
		t.Errorf("hours = %d, want 720 (clamped)", capturedHours)
	}
}

func TestThreatHandler_GetTimeline_Success(t *testing.T) {
	ms := &mockStore{
		getThreatTimelineFunc: func(_ context.Context, _ string, _ int) ([]store.ThreatTimelinePoint, error) {
			return []store.ThreatTimelinePoint{
				{Hour: "2024-01-01 00:00", Dlp: 3, Injection: 1, Semantic: 0},
			}, nil
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/timeline", nil)
	rr := httptest.NewRecorder()
	h.GetTimeline(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var pts []store.ThreatTimelinePoint
	if err := json.NewDecoder(rr.Body).Decode(&pts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pts) != 1 {
		t.Errorf("got %d points, want 1", len(pts))
	}
}

func TestThreatHandler_GetTimeline_NilSlice(t *testing.T) {
	h := NewThreatHandler(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/timeline", nil)
	rr := httptest.NewRecorder()
	h.GetTimeline(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("body = %q, want []", body)
	}
}

func TestThreatHandler_GetTopPatterns_Success(t *testing.T) {
	ms := &mockStore{
		getTopThreatPatternsFunc: func(_ context.Context, _ string, _ int, limit int) ([]store.ThreatPattern, error) {
			return []store.ThreatPattern{
				{Type: "dlp", PatternName: "ssn_pattern", Category: "pii", TotalCount: 15, EventCount: 10},
				{Type: "injection", PatternName: "sql_inject", TotalCount: 5, EventCount: 3},
			}, nil
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/top-patterns?limit=10", nil)
	rr := httptest.NewRecorder()
	h.GetTopPatterns(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var patterns []store.ThreatPattern
	if err := json.NewDecoder(rr.Body).Decode(&patterns); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(patterns) != 2 {
		t.Errorf("got %d patterns, want 2", len(patterns))
	}
	if patterns[0].PatternName != "ssn_pattern" {
		t.Errorf("first pattern = %q, want ssn_pattern", patterns[0].PatternName)
	}
}

func TestThreatHandler_GetTopPatterns_StoreError(t *testing.T) {
	ms := &mockStore{
		getTopThreatPatternsFunc: func(_ context.Context, _ string, _ int, _ int) ([]store.ThreatPattern, error) {
			return nil, errStore
		},
	}
	h := NewThreatHandler(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threats/top-patterns", nil)
	rr := httptest.NewRecorder()
	h.GetTopPatterns(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestPasswordHashingAndVerification(t *testing.T) {
	pass := "mySecretPass123!"
	hash, err := hashPassword(pass)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}

	ok, err := VerifyPassword(pass, hash)
	if err != nil || !ok {
		t.Errorf("VerifyPassword failed for correct password: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrongPassword", hash)
	if ok {
		t.Errorf("VerifyPassword succeeded for wrong password!")
	}
}
