package model

import "time"

// RequestAttribution represents an immutable audit record linking live LLM traffic to identity & desired state (REQ-VER-003).
type RequestAttribution struct {
	ID               string    `json:"id"`
	RequestID        string    `json:"request_id"`
	OrganizationID   string    `json:"organization_id"`
	DeviceID         string    `json:"device_id"`
	UserID           string    `json:"user_id"`
	IdentitySource   string    `json:"identity_source"` // "local_os" vs "oidc"
	IdentityVerified bool      `json:"identity_verified"`
	AssignmentID     *string   `json:"assignment_id,omitempty"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	StatusCode       int       `json:"status_code"`
	InputTokens      int64     `json:"input_tokens"`
	OutputTokens     int64     `json:"output_tokens"`
	CreatedAt        time.Time `json:"created_at"`
}

// RequestIdentity carries caller identity into the broker forwarding methods (REQ-VER-001).
type RequestIdentity struct {
	OrganizationID   string
	DeviceID         string
	UserID           string
	IdentitySource   string // "local_os" vs "oidc"
	IdentityVerified bool
	AssignmentID     string
}
