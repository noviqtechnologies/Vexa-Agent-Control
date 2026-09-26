package device

import "time"

// Multi-State Capability Vectors (PRD Rev 3.3)
const (
	TargetStateNotDetected        = "NOT_DETECTED"
	TargetStateDetected           = "DETECTED"
	TargetStateConfigured         = "CONFIGURED"
	TargetStateMcpWrapped         = "MCP_WRAPPED"
	TargetStateProbeVerified      = "PROBE_VERIFIED"
	TargetStateTrafficVerified    = "TRAFFIC_VERIFIED"
	TargetStateMcpTrafficVerified = "MCP_TRAFFIC_VERIFIED"
	TargetStateBypassPossible     = "BYPASS_POSSIBLE"
	TargetStateNotInstalled       = "NOT_INSTALLED"

	// Deprecated legacy aliases
	ComplianceStateCompliant    = "CONFIGURED"
	ComplianceStateNonCompliant = "BYPASS_POSSIBLE"
	ComplianceStateOffline      = "OFFLINE"
	ComplianceStateBypassed     = "BYPASS_POSSIBLE"
	ComplianceStateNotInstalled = "NOT_INSTALLED"
)

// Enrollment status
const (
	EnrollmentStatusActive    = "ACTIVE"
	EnrollmentStatusRevoked   = "REVOKED"
	EnrollmentStatusSuspended = "SUSPENDED"
)

// Tamper event types
const (
	EventTypeConfigTampered = "CONFIG_TAMPERED"
	EventTypeAutoHealed     = "AUTO_HEALED"
	EventTypeDaemonDisabled = "DAEMON_DISABLED"
	EventTypeProxyBypassed  = "PROXY_BYPASSED"
)

// DeviceEnrollment represents a registered developer workstation
type DeviceEnrollment struct {
	DeviceID         string     `json:"device_id"`
	OrganizationID   string     `json:"organization_id"`
	Hostname         string     `json:"hostname"`
	UserIdentifier   string     `json:"user_identifier"`
	OS               string     `json:"os"`
	OSVersion        string     `json:"os_version"`
	PublicKey        string     `json:"public_key"`
	DaemonVersion    string     `json:"daemon_version"`
	EnrollmentStatus string     `json:"enrollment_status"`
	LastHeartbeatAt  *time.Time `json:"last_heartbeat_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// EnrollDeviceRequest represents enrollment payload from workstation
type EnrollDeviceRequest struct {
	Hostname       string `json:"hostname"`
	UserIdentifier string `json:"user_identifier"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	PublicKey      string `json:"public_key"`
	DaemonVersion  string `json:"daemon_version"`
	InviteToken    string `json:"invite_token,omitempty"`
}

// EnrollDeviceResponse represents successful enrollment response
type EnrollDeviceResponse struct {
	DeviceID        string    `json:"device_id"`
	OrganizationID  string    `json:"organization_id"`
	Status          string    `json:"status"`
	LocalProxyToken string    `json:"local_proxy_token"`
	EnrolledAt      time.Time `json:"enrolled_at"`
}

// IdeTargetStatus represents configuration state of a single IDE on workstation
type IdeTargetStatus struct {
	Name               string     `json:"name"`
	Installed          bool       `json:"installed"`
	ConfigPath         string     `json:"config_path,omitempty"`
	ProxyConfigured    bool       `json:"proxy_configured"`
	ConfiguredBaseURL  string     `json:"configured_base_url,omitempty"`
	McpWrapped         bool       `json:"mcp_wrapped"`
	ComplianceState    string     `json:"compliance_state"`
	LastHealedAt       *time.Time `json:"last_healed_at,omitempty"`
}

// TamperEventPayload represents a tampering or auto-healing incident
type TamperEventPayload struct {
	IdeName            string    `json:"ide_name"`
	EventType          string    `json:"event_type"`
	TamperDetails      string    `json:"tamper_details"`
	HealedSuccessfully bool      `json:"healed_successfully"`
	OccurredAt         time.Time `json:"occurred_at"`
}

// TelemetryHeartbeatRequest represents the periodic 60s report from workstation
type TelemetryHeartbeatRequest struct {
	DeviceID          string               `json:"device_id"`
	OverallCompliance string               `json:"overall_compliance"`
	IdeTargets        []IdeTargetStatus    `json:"ide_targets"`
	TamperEvents      []TamperEventPayload `json:"tamper_events,omitempty"`
	Timestamp         time.Time            `json:"timestamp"`
}

// TelemetryHeartbeatResponse acknowledges heartbeat receipt
type TelemetryHeartbeatResponse struct {
	Acknowledged                 bool   `json:"acknowledged"`
	NextHeartbeatIntervalSeconds int    `json:"next_heartbeat_interval_seconds"`
	PolicyVersion                string `json:"policy_version,omitempty"`
}

// DeviceComplianceSummary represents overview of a device in admin console
type DeviceComplianceSummary struct {
	DeviceID          string     `json:"device_id"`
	Hostname          string     `json:"hostname"`
	UserIdentifier    string     `json:"user_identifier"`
	OS                string     `json:"os"`
	OSVersion         string     `json:"os_version"`
	OverallCompliance string     `json:"overall_compliance"`
	ActiveIDEs        []string   `json:"active_ides"`
	TamperCount24h    int        `json:"tamper_count_24h"`
	LastHeartbeatAt   *time.Time `json:"last_heartbeat_at,omitempty"`
	EnrollmentStatus  string     `json:"enrollment_status"`
}

// ListDevicesResponse represents fleet inventory response
type ListDevicesResponse struct {
	Devices           []DeviceComplianceSummary `json:"devices"`
	TotalCount        int                       `json:"total_count"`
	CompliantCount    int                       `json:"compliant_count"`
	NonCompliantCount int                       `json:"non_compliant_count"`
	OfflineCount      int                       `json:"offline_count"`
}

// DeviceTamperEventLog represents an entry in the immutable audit explorer
type DeviceTamperEventLog struct {
	EventID            string    `json:"event_id"`
	DeviceID           string    `json:"device_id"`
	Hostname           string    `json:"hostname"`
	UserIdentifier     string    `json:"user_identifier"`
	IdeName            string    `json:"ide_name"`
	EventType          string    `json:"event_type"`
	TamperDetails      string    `json:"tamper_details"`
	HealedSuccessfully bool      `json:"healed_successfully"`
	OccurredAt         time.Time `json:"occurred_at"`
}

// ListTamperEventsResponse represents tamper log list
type ListTamperEventsResponse struct {
	Events     []DeviceTamperEventLog `json:"events"`
	TotalCount int                    `json:"total_count"`
}

// DeviceDetailResponse represents complete granular telemetry and governance detail for a single device
type DeviceDetailResponse struct {
	DeviceID           string                 `json:"device_id"`
	OrganizationID     string                 `json:"organization_id"`
	Hostname           string                 `json:"hostname"`
	UserIdentifier     string                 `json:"user_identifier"`
	OS                 string                 `json:"os"`
	OSVersion          string                 `json:"os_version"`
	PublicKey          string                 `json:"public_key"`
	DaemonVersion      string                 `json:"daemon_version"`
	EnrollmentStatus   string                 `json:"enrollment_status"`
	LastHeartbeatAt    *time.Time             `json:"last_heartbeat_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	OverallCompliance  string                 `json:"overall_compliance"`
	TamperCount24h     int                    `json:"tamper_count_24h"`
	IdeStatuses        []IdeTargetStatus      `json:"ide_statuses"`
	RecentTamperEvents []DeviceTamperEventLog `json:"recent_tamper_events"`
	ReportPayload      string                 `json:"report_payload,omitempty"`
}

// ClientLogEntry represents a structured diagnostic error/warning logged on a client gateway
type ClientLogEntry struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organization_id"`
	DeviceID       string                 `json:"device_id"`
	Hostname       string                 `json:"hostname,omitempty"`
	UserIdentifier string                 `json:"user_identifier,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	Level          string                 `json:"level"`
	Event          string                 `json:"event"`
	ErrorCode      string                 `json:"error_code,omitempty"`
	Message        string                 `json:"message,omitempty"`
	Origin         string                 `json:"origin,omitempty"`
	RequestID      string                 `json:"request_id,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
}

// ClientLogsIngestRequest represents batch client error logs sent by agentwall
type ClientLogsIngestRequest struct {
	DeviceID       string                   `json:"device_id"`
	Hostname       string                   `json:"hostname,omitempty"`
	UserIdentifier string                   `json:"user_identifier,omitempty"`
	Logs           []map[string]interface{} `json:"logs"`
	Timestamp      time.Time                `json:"timestamp"`
}

// ClientLogQuery defines query parameters for fetching client logs
type ClientLogQuery struct {
	Limit     int
	Offset    int
	DeviceID  string
	Level     string
	Event     string
	RequestID string
	Search    string
	Since     time.Time
}

