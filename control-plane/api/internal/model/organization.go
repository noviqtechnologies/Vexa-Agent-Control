package model

import "time"

type OrganizationStatus string

const (
	OrgStatusActive       OrganizationStatus = "active"
	OrgStatusSuspended    OrganizationStatus = "suspended"
	OrgStatusTrialExpired OrganizationStatus = "trial_expired"
	OrgStatusClosed       OrganizationStatus = "closed"
)

type Organization struct {
	ID                  string             `json:"id" db:"id"`
	Name                string             `json:"name" db:"name"`
	Slug                string             `json:"slug" db:"slug"`
	ContactEmail        string             `json:"contact_email" db:"contact_email"`
	LicenseTier         string             `json:"license_tier" db:"license_tier"` // "developer", "team", "enterprise"
	MaxDevices          int                `json:"max_devices" db:"max_devices"`
	EnrolledDevices     int                `json:"enrolled_devices" db:"-"`
	LicenseKeyJWT       string             `json:"license_key_jwt,omitempty" db:"license_key_jwt"`
	LicenseExpiresAt    *time.Time         `json:"license_expires_at,omitempty" db:"license_expires_at"`
	Status              OrganizationStatus `json:"status" db:"status"`
	CreatedAt           time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at" db:"updated_at"`
}

type UpdateOrgReq struct {
	Name         string `json:"name"`
	ContactEmail string `json:"contact_email"`
}

type ActivateLicenseReq struct {
	LicenseKeyJWT string `json:"license_key_jwt"`
}

type OrganizationSummary struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Slug             string             `json:"slug"`
	ContactEmail     string             `json:"contact_email"`
	LicenseTier      string             `json:"license_tier"`
	MaxDevices       int                `json:"max_devices"`
	EnrolledDevices  int                `json:"enrolled_devices"`
	LicenseExpiresAt *time.Time         `json:"license_expires_at,omitempty"`
	DaysRemaining    int                `json:"days_remaining"`
	Status           OrganizationStatus `json:"status"`
	CreatedAt        time.Time          `json:"created_at"`
}

type CreateOrgReq struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	ContactEmail string `json:"contact_email"`
	LicenseTier  string `json:"license_tier"`
	MaxSeats     int    `json:"max_seats"`
	ValidDays    int    `json:"valid_days"`
	IsTrial      bool   `json:"is_trial"`
	TrialDays    int    `json:"trial_days"`
}

type RenewLicenseReq struct {
	AdditionalDays int  `json:"additional_days"`
	IsTrial        bool `json:"is_trial"`
}
