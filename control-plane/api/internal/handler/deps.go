package handler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// DataStore abstracts the persistence layer so handlers can be unit-tested
// without a live database.
type DataStore interface {
	GetFleetStats(ctx context.Context, tenantID string, hours int) (*store.FleetStats, error)
	ListAgents(ctx context.Context, tenantID string, limit, offset int, hours int) ([]store.AgentSummary, error)
	GetDecisionHeatmap(ctx context.Context, tenantID string, hours int) ([]store.DecisionBreakdown, error)
	ListRecentEvents(ctx context.Context, tenantID, agentID string, limit int) ([]store.RecentEvent, error)

	ListCredentials(ctx context.Context, tenantID, agentID string) ([]model.SanitizedCredentialMeta, error)

	UpsertAgent(ctx context.Context, tenantID, agentID string) error
	CountDistinctAgents(ctx context.Context, tenantID string) (int, error)
	AgentExists(ctx context.Context, tenantID, agentID string) (bool, error)
	ResolveTenantIDForAgent(ctx context.Context, agentID string) string
	InsertEvent(ctx context.Context, tenantID string, e *model.RedactedEvent) error
	InsertAlert(ctx context.Context, tenantID string, a *model.RedactedAlert) error
	UpsertCredential(ctx context.Context, tenantID string, c *model.SanitizedCredentialMeta) error

	ListRecentAlerts(ctx context.Context, tenantID string, limit int, hours int) ([]model.RedactedAlert, error)

	GetThreatSummary(ctx context.Context, tenantID string, hours int) (*store.ThreatSummary, error)
	GetThreatTimeline(ctx context.Context, tenantID string, hours int) ([]store.ThreatTimelinePoint, error)
	GetTopThreatPatterns(ctx context.Context, tenantID string, hours int, limit int) ([]store.ThreatPattern, error)

	UpsertMcpServer(ctx context.Context, tenantID, agentID string, m *model.SanitizedMcpServerMeta) error
	ListMcpServersByAgent(ctx context.Context, tenantID, agentID string) ([]store.McpServerInventoryRow, error)
	ListMcpServersFleetWide(ctx context.Context, tenantID string) ([]store.McpServerInventoryRow, error)

	UpsertSpendBudget(ctx context.Context, tenantID string, b *store.SpendBudget) error
	ListSpendBudgets(ctx context.Context, tenantID string) ([]store.SpendBudget, error)
	UpsertSpendSnapshot(ctx context.Context, tenantID string, snap *store.SpendSnapshot) error
	ListSpendSnapshots(ctx context.Context, tenantID string) ([]store.SpendSnapshot, error)
	InsertIncreaseRequest(ctx context.Context, tenantID string, r *store.IncreaseRequest) error
	ResolveIncreaseRequest(ctx context.Context, tenantID, id string, status string, resolvedBy string, newCap *int64) error
	ListIncreaseRequests(ctx context.Context, tenantID string) ([]store.IncreaseRequest, error)

	GetActiveGroupPolicy(ctx context.Context, tenantID, groupID string) (*store.GroupPolicyVersion, error)
	PublishGroupPolicy(ctx context.Context, tenantID, groupID string, claims json.RawMessage, tools json.RawMessage, createdBy string) (*store.GroupPolicyVersion, error)
	ListGroupPolicies(ctx context.Context, tenantID string) ([]*store.GroupPolicyVersion, error)

	InsertProviderKey(ctx context.Context, tenantID string, k *store.ProviderKey) error
	ListProviderKeys(ctx context.Context, tenantID string) ([]store.ProviderKey, error)
	DeleteProviderKey(ctx context.Context, tenantID, id string) error
	GetProviderKeyByProvider(ctx context.Context, tenantID, provider string) (*store.ProviderKey, error)

	// Pillar 1: Scoped Virtual Keys
	CreateVirtualKey(ctx context.Context, tenantID string, k *store.VirtualKey) error
	ListVirtualKeys(ctx context.Context, tenantID string) ([]store.VirtualKey, error)
	GetVirtualKeyByID(ctx context.Context, tenantID, id string) (*store.VirtualKey, error)
	GetVirtualKeyByHash(ctx context.Context, keyHash string) (*store.VirtualKey, error)
	RotateVirtualKey(ctx context.Context, tenantID, id string, newKeyHash, newKeyPrefix string, gracePeriod time.Duration) (*store.VirtualKey, error)
	DeleteVirtualKey(ctx context.Context, tenantID, id string) error
	IncrementVirtualKeySpend(ctx context.Context, tenantID, id string, deltaMicrocents int64) (int64, error)
	ResetVirtualKeySpend(ctx context.Context, tenantID, id string) error

	// Central Provider Key Vault (AES-256-GCM envelope encryption)
	InsertEncryptedProviderKey(ctx context.Context, tenantID, provider, keyAlias, plainSecret string, kmsProvider kms.KMSProvider) error
	GetDecryptedProviderKey(ctx context.Context, tenantID, provider string, kmsProvider kms.KMSProvider) (string, error)
	ListEncryptedProviderKeys(ctx context.Context, tenantID string) ([]store.ProviderKeyMeta, error)
	DeleteEncryptedProviderKey(ctx context.Context, tenantID, provider string) error
}
