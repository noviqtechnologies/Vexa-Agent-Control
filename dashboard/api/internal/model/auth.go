package model

import "time"

type AuthProvider struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"` // "local", "github", "google"
	Name         string    `json:"name"`
	ClientID     string    `json:"client_id,omitempty"`
	ClientSecret string    `json:"client_secret,omitempty"` // Note: normally don't send this to frontend, omit from API responses if necessary
	IssuerURL    string    `json:"issuer_url,omitempty"`
	Enabled      bool      `json:"enabled"`
	EmailDomains []string  `json:"email_domains"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type User struct {
	ID             string    `json:"id"`
	AuthProviderID string    `json:"auth_provider_id"`
	Email          string    `json:"email"`
	PasswordHash   string    `json:"-"` // never exposed
	IsAdmin        bool      `json:"is_admin"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
