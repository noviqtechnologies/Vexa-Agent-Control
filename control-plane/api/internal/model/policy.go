package model

import "time"

type Policy struct {
	ID        string    `json:"id"`
	Version   string    `json:"version"`
	Content   string    `json:"content"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PolicyTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Categories  []string  `json:"categories,omitempty"`
	Complexity  string    `json:"complexity,omitempty"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	Guardrails  []string  `json:"guardrails,omitempty"`
	Icon        string    `json:"icon"`
	Content     string    `json:"content"`
	IsCustom    bool      `json:"is_custom"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SignedPolicyBundle represents a cryptographically signed policy envelope (Gate 3.2).
// Exactly matches the Rust SignedPolicyBundle format in src/policy/signed.rs.
type SignedPolicyBundle struct {
	SchemaVersion  string  `json:"schema_version"`
	PolicyID       string  `json:"policy_id"`
	PolicyRevision uint64  `json:"policy_revision"`
	PolicyYaml     string  `json:"policy_yaml"`
	Signature      string  `json:"signature"`
	PublicKey      string  `json:"public_key"`
	IssuedAt       string  `json:"issued_at"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
}


