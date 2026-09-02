package model

import "time"

type AuthProvider struct {
	ID             string    `json:"id" db:"id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	Type           string    `json:"type" db:"type"` // "local", "oidc", "saml"
	Name           string    `json:"name" db:"name"`
	ClientID       string    `json:"client_id,omitempty" db:"client_id"`
	ClientSecret   string    `json:"client_secret,omitempty" db:"client_secret"`
	IssuerURL      string    `json:"issuer_url,omitempty" db:"issuer_url"`
	Enabled        bool      `json:"enabled" db:"enabled"`
	EmailDomains   []string  `json:"email_domains" db:"email_domains"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

type User struct {
	ID             string    `json:"id" db:"id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	AuthProviderID *string   `json:"auth_provider_id,omitempty" db:"auth_provider_id"`
	Email          string    `json:"email" db:"email"`
	PasswordHash   string    `json:"-" db:"password_hash"`
	IsAdmin        bool      `json:"is_admin" db:"is_admin"`
	Role           string    `json:"role" db:"role"` // "OWNER", "ADMIN", "MEMBER", "VIEWER"
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}
