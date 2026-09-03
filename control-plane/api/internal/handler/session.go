package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// SessionHandler handles agent session timeline & multi-turn forensics.
type SessionHandler struct {
	spendStore *spend.Store
	store      DataStore
}

// NewSessionHandler creates a new SessionHandler.
func NewSessionHandler(ss *spend.Store, ds DataStore) *SessionHandler {
	return &SessionHandler{
		spendStore: ss,
		store:      ds,
	}
}

// SessionTimelineItem represents one step in the unified session trajectory.
type SessionTimelineItem struct {
	Type      string             `json:"type"` // "llm_completion" | "tool_call"
	Timestamp time.Time          `json:"timestamp"`
	LLMRun    *spend.RunSummary  `json:"llm_run,omitempty"`
	ToolEvent *store.RecentEvent `json:"tool_event,omitempty"`
}

// SessionTraceResponse represents the complete forensics of an agent session.
type SessionTraceResponse struct {
	SessionID string `json:"session_id"`
	Summary   struct {
		TotalLLMCalls            int       `json:"total_llm_calls"`
		TotalToolCalls           int       `json:"total_tool_calls"`
		TotalTokens              int64     `json:"total_tokens"`
		TotalCachedTokens        int64     `json:"total_cached_tokens"`
		TotalSettledMicrocents   int64     `json:"total_settled_microcents"`
		PolicyInterventionsCount int       `json:"policy_interventions_count"`
		StartedAt                time.Time `json:"started_at"`
		EndedAt                  time.Time `json:"ended_at"`
		DurationMs               int64     `json:"duration_ms"`
	} `json:"summary"`
	Timeline []SessionTimelineItem `json:"timeline"`
}

// GetSessionTrace handles GET /api/v1/sessions/{session_id}
func (h *SessionHandler) GetSessionTrace(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.ResolveTenantScope(r)
	if tenantID == "" {
		tenantID = middleware.TenantIDFromContext(r.Context())
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" {
		http.Error(w, `{"error":"missing session_id"}`, http.StatusBadRequest)
		return
	}

	// 1. Fetch all LLM completions for this session
	runs, err := h.spendStore.ListRuns(r.Context(), tenantID, spend.RunQuery{
		SessionID: sessionID,
		Limit:     200,
	})
	if err != nil {
		http.Error(w, `{"error":"failed to fetch session LLM runs"}`, http.StatusInternalServerError)
		return
	}

	// 2. Fetch all MCP tool events for this session
	events, err := h.store.ListEventsBySession(r.Context(), tenantID, sessionID, 200)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch session tool events"}`, http.StatusInternalServerError)
		return
	}

	timeline := []SessionTimelineItem{}
	var totalTokens int64
	var totalCachedTokens int64
	var totalSettled int64
	var interventions int
	var earliest time.Time
	var latest time.Time

	for i := range runs {
		run := runs[i]
		ts := run.StartedAt
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
		if ts.After(latest) {
			latest = ts
		}

		totalTokens += run.TotalTokens
		totalCachedTokens += run.CachedTokens
		if strings.ToUpper(run.State) == "SETTLED" {
			totalSettled += int64(run.SettledMicrocents)
		}
		if strings.ToUpper(run.State) == "DENIED" || strings.ToUpper(run.State) == "BLOCKED" {
			interventions++
		}

		timeline = append(timeline, SessionTimelineItem{
			Type:      "llm_completion",
			Timestamp: ts,
			LLMRun:    &run,
		})
	}

	for i := range events {
		evt := events[i]
		ts := time.UnixMilli(evt.TimestampMs).UTC()
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
		if ts.After(latest) {
			latest = ts
		}

		dec := strings.ToLower(evt.Decision)
		if dec == "deny" || dec == "denied" || dec == "blocked" || dec == "warn" || dec == "redact" || len(evt.DlpFindings) > 0 || len(evt.InjectionFindings) > 0 {
			interventions++
		}

		timeline = append(timeline, SessionTimelineItem{
			Type:      "tool_call",
			Timestamp: ts,
			ToolEvent: &evt,
		})
	}

	// Chronologically interleave events
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})

	durationMs := int64(0)
	if !earliest.IsZero() && !latest.IsZero() {
		durationMs = latest.Sub(earliest).Milliseconds()
		if durationMs < 0 {
			durationMs = 0
		}
	}

	resp := SessionTraceResponse{
		SessionID: sessionID,
		Timeline:  timeline,
	}
	resp.Summary.TotalLLMCalls = len(runs)
	resp.Summary.TotalToolCalls = len(events)
	resp.Summary.TotalTokens = totalTokens
	resp.Summary.TotalCachedTokens = totalCachedTokens
	resp.Summary.TotalSettledMicrocents = totalSettled
	resp.Summary.PolicyInterventionsCount = interventions
	resp.Summary.StartedAt = earliest
	resp.Summary.EndedAt = latest
	resp.Summary.DurationMs = durationMs

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
