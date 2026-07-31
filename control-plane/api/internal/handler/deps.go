package handler

import (
	"context"
	"encoding/json"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
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

	UpsertMcpServer(ctx context.Context, agentID string, m *model.SanitizedMcpServerMeta) error
	ListMcpServersByAgent(ctx context.Context, agentID string) ([]store.McpServerInventoryRow, error)
	ListMcpServersFleetWide(ctx context.Context) ([]store.McpServerInventoryRow, error)

	UpsertSpendBudget(ctx context.Context, b *store.SpendBudget) error
	ListSpendBudgets(ctx context.Context) ([]store.SpendBudget, error)
	UpsertSpendSnapshot(ctx context.Context, snap *store.SpendSnapshot) error
	ListSpendSnapshots(ctx context.Context) ([]store.SpendSnapshot, error)
	InsertIncreaseRequest(ctx context.Context, r *store.IncreaseRequest) error
	ResolveIncreaseRequest(ctx context.Context, id string, status string, resolvedBy string, newCap *int64) error
	ListIncreaseRequests(ctx context.Context) ([]store.IncreaseRequest, error)

	GetActiveGroupPolicy(ctx context.Context, groupID string) (*store.GroupPolicyVersion, error)
	PublishGroupPolicy(ctx context.Context, groupID string, claims json.RawMessage, tools json.RawMessage, createdBy string) (*store.GroupPolicyVersion, error)
	ListGroupPolicies(ctx context.Context) ([]*store.GroupPolicyVersion, error)

	InsertProviderKey(ctx context.Context, k *store.ProviderKey) error
	ListProviderKeys(ctx context.Context) ([]store.ProviderKey, error)
	DeleteProviderKey(ctx context.Context, id string) error
}
