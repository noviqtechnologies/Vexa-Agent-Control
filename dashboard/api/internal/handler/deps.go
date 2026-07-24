package handler

import (
	"context"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

// DataStore abstracts the persistence layer so handlers can be unit-tested
// without a live database.
type DataStore interface {
	GetFleetStats(ctx context.Context) (*store.FleetStats, error)
	ListAgents(ctx context.Context, limit, offset int) ([]store.AgentSummary, error)
	GetDecisionHeatmap(ctx context.Context, hours int) ([]store.DecisionBreakdown, error)
	ListRecentEvents(ctx context.Context, agentID string, limit int) ([]store.RecentEvent, error)

	ListCredentials(ctx context.Context, agentID string) ([]model.SanitizedCredentialMeta, error)

	UpsertAgent(ctx context.Context, agentID string) error
	InsertEvent(ctx context.Context, e *model.RedactedEvent) error
	InsertAlert(ctx context.Context, a *model.RedactedAlert) error
	UpsertCredential(ctx context.Context, c *model.SanitizedCredentialMeta) error

	ListRecentAlerts(ctx context.Context, limit int) ([]model.RedactedAlert, error)

	GetThreatSummary(ctx context.Context, hours int) (*store.ThreatSummary, error)
	GetThreatTimeline(ctx context.Context, hours int) ([]store.ThreatTimelinePoint, error)
	GetTopThreatPatterns(ctx context.Context, hours int, limit int) ([]store.ThreatPattern, error)
}
