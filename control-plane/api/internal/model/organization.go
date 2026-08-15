package model

import "time"

type OrganizationStatus string

const (
	OrgStatusActive       OrganizationStatus = "ACTIVE"
	OrgStatusSuspended    OrganizationStatus = "SUSPENDED"
	OrgStatusTrialExpired OrganizationStatus = "TRIAL_EXPIRED"
	OrgStatusClosed       OrganizationStatus = "CLOSED"
)

type Organization struct {
	ID                  string             `json:"id"`
	Name                string             `json:"name"`
	Slug                string             `json:"slug"`
	ContactEmail        string             `json:"contact_email"`
	LicenseTier         string             `json:"license_tier"` // "community", "team", "enterprise"
	MaxSeats            int                `json:"max_seats"`
	LicenseKeyJWT       string             `json:"license_key_jwt,omitempty"`
	IsTrial             bool               `json:"is_trial"`
	TrialDays           int                `json:"trial_days"`
	TrialEndsAt         *time.Time         `json:"trial_ends_at,omitempty"`
	LicenseExpiresAt    *time.Time         `json:"license_expires_at,omitempty"`
	GatewaySecret       string             `json:"gateway_secret,omitempty"`
	PolicyReadSecret    string             `json:"policy_read_secret,omitempty"`
	BootstrapTokenHash  string             `json:"-"`
	BootstrapTokenHint  string             `json:"bootstrap_token_hint,omitempty"`
	BootstrapConsumedAt *time.Time         `json:"bootstrap_consumed_at,omitempty"`
	Status              OrganizationStatus `json:"status"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
}

type CreateOrgReq struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	ContactEmail string `json:"contact_email"`
	LicenseTier  string `json:"license_tier"` // "community", "team", "enterprise"
	MaxSeats     int    `json:"max_seats"`
	IsTrial      bool   `json:"is_trial"`
	TrialDays    int    `json:"trial_days"` // 15 or 30
	ValidDays    int    `json:"valid_days"` // custom agreed days e.g. 365
}

type UpdateOrgReq struct {
	Name         string `json:"name"`
	ContactEmail string `json:"contact_email"`
	LicenseTier  string `json:"license_tier"`
	MaxSeats     int    `json:"max_seats"`
}

type RenewLicenseReq struct {
	AdditionalDays int  `json:"additional_days"` // e.g. 15, 30, 365
	IsTrial        bool `json:"is_trial"`
}

type OrgSummary struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Slug             string             `json:"slug"`
	ContactEmail     string             `json:"contact_email"`
	LicenseTier      string             `json:"license_tier"`
	MaxSeats         int                `json:"max_seats"`
	IsTrial          bool               `json:"is_trial"`
	TrialDays        int                `json:"trial_days"`
	TrialEndsAt      *time.Time         `json:"trial_ends_at,omitempty"`
	LicenseExpiresAt *time.Time         `json:"license_expires_at,omitempty"`
	DaysRemaining    int                `json:"days_remaining"`
	Status           OrganizationStatus `json:"status"`
	CreatedAt        time.Time          `json:"created_at"`
	HasBootstrap     bool               `json:"has_bootstrap"`
}

type PlatformStats struct {
	TotalOrganizations int `json:"total_organizations"`
	ActiveTrials       int `json:"active_trials"`
	ExpiringWithin7d   int `json:"expiring_within_7d"`
	TotalSeats         int `json:"total_seats"`
}
