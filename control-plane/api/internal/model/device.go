package model

import "time"

type Device struct {
	DeviceID          string                 `json:"device_id"`
	Hostname          string                 `json:"hostname"`
	OSArch            string                 `json:"os_arch"`
	OSFamily          string                 `json:"os_family"`
	PublicKey         string                 `json:"public_key"`
	AgentControlVersion  string                 `json:"agentcontrol_version"`
	ComplianceStatus  string                 `json:"compliance_status"`
	MCPServersTotal   int                    `json:"mcp_servers_total"`
	MCPServersWrapped int                    `json:"mcp_servers_wrapped"`
	IDEChecksums       map[string]interface{} `json:"ide_checksums"`
	FirstEnrolledAt   time.Time              `json:"first_enrolled_at"`
	LastHeartbeatAt   time.Time              `json:"last_heartbeat_at"`
	IsRevoked         bool                   `json:"is_revoked"`
	RevokedAt         *time.Time             `json:"revoked_at,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

type EnrollmentToken struct {
	TokenID     string    `json:"token_id"`
	TokenHash   string    `json:"token_hash"`
	CreatedBy   string    `json:"created_by"`
	MaxUses     int       `json:"max_uses"`
	CurrentUses int       `json:"current_uses"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type DeviceTamperLog struct {
	LogID        string    `json:"log_id"`
	DeviceID     string    `json:"device_id"`
	TargetIDE    string    `json:"target_ide"`
	DetectedDiff string    `json:"detected_diff"`
	ActionTaken  string    `json:"action_taken"`
	CreatedAt    time.Time `json:"created_at"`
}
