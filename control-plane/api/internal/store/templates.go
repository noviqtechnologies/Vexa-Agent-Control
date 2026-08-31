package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var builtinTemplates = []*model.PolicyTemplate{
	{
		ID:          "safe-cursor",
		Name:        "Safe Cursor Workstation",
		Category:    "Developer Security",
		Description: "Blocks destructive shell operations (rm -rf, mkfs, dd), shields .env, id_rsa, and credentials, and stops post-read secret exfiltration.",
		Tags:        []string{"IDE", "Cursor", "Developer", "Filesystem"},
		Icon:        "shield-check",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 10

llm:
  cursor_mode: byok
  model_enforcement: restrict
  allowed_models:
    - "claude-3-5-sonnet*"
    - "gpt-4o*"
    - "gemini-1.5-pro*"
  providers:
    - name: "anthropic"
      action: "allow"
      models: ["claude*"]
    - name: "openai"
      action: "allow"
      models: ["gpt*"]
    - name: "google"
      action: "allow"
      models: ["gemini*"]

sequence_rules:
  - name: block_exfiltration_after_reading_secrets
    window_size: 5
    antecedent_tools:
      - read_file
      - view_file
    antecedent_param_regex: ".*(\\.env|id_rsa|aws/credentials|secrets|token).*"
    consequent_tools:
      - http_post
      - fetch_url
      - exec_shell
    action: block
    message: "Security Violation: Blocked outbound call after reading sensitive credential file."

tools:
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(rm\\s+-rf|mkfs|dd\\s+if|chmod\\s+-R\\s+777|sudo\\s+rm)).*$"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials|id_ed25519|\\.pem)).*$"
        validators:
          - path_traversal

  - name: list_directory
    action: allow
    parameters:
      - name: directory
        type: string
        required: true

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "cursor-byok-governance",
		Name:        "Cursor IDE & Zero-Trust BYOK Governance",
		Category:    "Developer Security",
		Description: "Enforces centralized BYOK API key injection and TLS MITM interception for Cursor. Restricts developer model usage to company-approved LLMs and blocks unvetted models.",
		Tags:        []string{"Cursor", "BYOK", "TLS Interception", "Model Governance"},
		Icon:        "lock",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

# Centralized BYOK and MITM Model Allowlisting
llm:
  cursor_mode: byok
  model_enforcement: restrict
  allowed_models:
    - "claude-3-5-sonnet*"
    - "gpt-4o*"
    - "gemini-1.5-pro*"
  providers:
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*"]
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials)).*$"
        validators:
          - path_traversal
  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(sudo|rm\\s+-rf|mkfs)).*$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "multicloud-llm-gateway",
		Name:        "Unified Multi-Cloud LLM Gateway",
		Category:    "Enterprise Security",
		Description: "Centralizes governance across OpenAI, Anthropic, and Google Gemini. Applies real-time DLP prompt & response redaction with rate limits.",
		Tags:        []string{"Enterprise", "Multi-Cloud", "OpenAI", "Anthropic", "Gemini", "DLP"},
		Icon:        "server",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 25

# Multi-Cloud LLM Provider Rules
llm:
  centralized_keys: true
  providers:
    - name: "openai"
      action: "allow"
      models:
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3*"
      dlp_tier: "strict"
    - name: "anthropic"
      action: "allow"
      models:
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"
    - name: "google"
      action: "allow"
      models:
        - "gemini-1.5-pro*"
        - "gemini-1.5-flash*"
        - "gemini-2.0-flash*"
      dlp_tier: "strict"

  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "PHONE_NUMBER"
        action: "redact"

response_scanning:
  enabled: true
  scan_level: "deep"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "pci-dss-compliance",
		Name:        "PCI-DSS & Financial Data Protection",
		Category:    "Finance & Compliance",
		Description: "Zero-tolerance financial security policy. Immediately blocks credit card numbers (Luhn validated), CVVs, and IBANs while restricting outbound egress to PCI boundaries.",
		Tags:        []string{"PCI-DSS", "Finance", "Credit Card", "DLP", "Compliance"},
		Icon:        "credit-card",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 10

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*"]
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "BANK_ACCOUNT"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal
  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true
  - name: http_request
    action: allow
    parameters:
      - name: url
        type: string
        required: true
        pattern: "^https://([a-zA-Z0-9-]+\\.)*(stripe\\.com|api\\.company\\.internal)(/.*)?$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "soc2-confidentiality",
		Name:        "SOC 2 & Codebase Confidentiality",
		Category:    "Enterprise Security",
		Description: "Enforces strict dotfile and credential shielding (.env, .git, .ssh, id_rsa, .pem), path traversal rejection, and non-bypassable session auditing.",
		Tags:        []string{"SOC2", "Confidentiality", "Filesystem", "Audit"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 20

sequence_rules:
  - name: block_exfiltration_after_reading_secrets
    window_size: 5
    antecedent_tools:
      - read_file
      - view_file
    antecedent_param_regex: ".*(\\.env|\\.git/|\\.ssh/|id_rsa|credentials).*"
    consequent_tools:
      - http_post
      - fetch_url
      - exec_shell
    action: block
    message: "SOC2 Compliance Violation: Outbound transmission blocked after reading sensitive asset."

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "gpt-4o-mini*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*", "gemini-1.5-flash*"]
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|\\.git|\\.ssh|id_rsa|\\.aws|\\.pem)).*$"
        validators:
          - path_traversal
  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.git|\\.ssh|/etc/|/var/)).*$"
      - name: content
        type: string
        required: true
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(rm\\s+-rf|mkfs|dd\\s+if|sudo|chmod\\s+-R\\s+777)).*$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "cost-governance-fallback",
		Name:        "LLM Cost Guardrails & Model Fallback",
		Category:    "Cost & Governance",
		Description: "Enforces automated model fallback to route costly requests (e.g. o1/opus) to cost-effective alternatives (gpt-4o-mini, gemini-1.5-flash) with tight rate limits.",
		Tags:        []string{"Cost", "FinOps", "Fallback", "Budget", "Rate Limiting"},
		Icon:        "dollar-sign",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 5

llm:
  model_enforcement: fallback
  default_model: "gpt-4o-mini"
  allowed_models:
    - "gpt-4o-mini"
    - "gemini-1.5-flash"
    - "claude-3-5-haiku"
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o-mini"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-flash"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-haiku"]

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "autonomous-agent-guardrails",
		Name:        "Autonomous Agent & MCP Guardrails",
		Category:    "Production Governance",
		Description: "Hardened sandbox for autonomous agent workflows (LangChain, AutoGPT, MCP). Enforces tool schema drift detection, cycle break prevention, and command safelists.",
		Tags:        []string{"Agents", "MCP", "Schema Drift", "Cycle Detection", "Sandbox"},
		Icon:        "bot",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 12

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*"]

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal
  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true
  - name: list_directory
    action: allow
    parameters:
      - name: directory
        type: string
        required: true
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(sudo|rm\\s+-rf|mkfs|dd|chmod|chown)).*$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error

schema_drift:
  enabled: true
  action: block
  baseline_path: "./schema_baselines.json"`,
	},
	{
		ID:          "production-data",
		Name:        "Production Egress & Drift Control",
		Category:    "Production Governance",
		Description: "Prevents data exfiltration by locking outbound requests to company domains, enforces cycle detection, and blocks MCP schema drift.",
		Tags:        []string{"Production", "Egress", "Firewall", "Schema Drift"},
		Icon:        "server",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

  - name: http_request
    action: allow
    parameters:
      - name: url
        type: string
        required: true
        pattern: "^https://([a-zA-Z0-9-]+\\.)*company\\.internal(/.*)?$"

  - name: query_db
    action: allow
    parameters:
      - name: query
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error

schema_drift:
  enabled: true
  action: block
  baseline_path: "./schema_baselines.json"`,
	},
	{
		ID:          "hipaa-compliance",
		Name:        "HIPAA & Medical PII Protection",
		Category:    "Healthcare & Compliance",
		Description: "Auto-redacts PHI, SSNs, Medical Record Numbers (MRN), and PII across LLM requests and agent responses.",
		Tags:        []string{"HIPAA", "DLP", "PHI", "Healthcare", "PII"},
		Icon:        "heart-pulse",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 10

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-4-turbo"]
      dlp_tier: "strict"
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet"]
      dlp_tier: "strict"
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "SSN"
        action: "deny"
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "PHONE_NUMBER"
        action: "redact"
      - entity: "MEDICAL_RECORD_NUMBER"
        action: "deny"
      - entity: "HEALTH_INFO"
        action: "redact"

response_scanning:
  enabled: true
  scan_level: "deep"
  patterns:
    - name: "ssn_pattern"
      regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      action: "redact"
    - name: "mrn_pattern"
      regex: "\\bMRN-\\d{6,8}\\b"
      action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "defense-in-depth",
		Name:        "Full Defense in Depth",
		Category:    "Enterprise Security",
		Description: "Comprehensive posture combining workstation shell protection, egress controls, and full LLM DLP redaction.",
		Tags:        []string{"Enterprise", "Full Protection", "DLP", "Firewall"},
		Icon:        "lock",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 20

sequence_rules:
  - name: block_exfiltration_after_reading_secrets
    window_size: 5
    antecedent_tools:
      - read_file
      - view_file
    antecedent_param_regex: ".*(\\.env|id_rsa|aws/credentials|secrets|token).*"
    consequent_tools:
      - http_post
      - fetch_url
      - exec_shell
    action: block
    message: "Security Violation: Blocked outbound call after reading sensitive credential file."

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-4-turbo"]
      dlp_tier: "strict"
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet"]
      dlp_tier: "strict"
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro", "gemini-1.5-flash"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

tools:
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(rm\\s+-rf|mkfs|dd\\s+if|chmod\\s+-R\\s+777)).*$"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials)).*$"
        validators:
          - path_traversal

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error

schema_drift:
  enabled: true
  action: block
  baseline_path: "./schema_baselines.json"`,
	},
}

// EnsureTemplatesTable creates the policy_templates table if it doesn't exist.
func (s *Store) EnsureTemplatesTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS policy_templates (
		id          TEXT PRIMARY KEY,
		tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
		name        TEXT NOT NULL,
		category    TEXT NOT NULL,
		description TEXT NOT NULL,
		tags        TEXT[] NOT NULL DEFAULT '{}',
		icon        TEXT NOT NULL DEFAULT 'shield',
		content     TEXT NOT NULL,
		is_custom   BOOLEAN NOT NULL DEFAULT true,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
	CREATE INDEX IF NOT EXISTS idx_policy_templates_tenant ON policy_templates(tenant_id);
	`
	_, err := s.pool.Exec(ctx, query)
	return err
}

func (s *Store) ListTemplates(ctx context.Context, tenantID string) ([]*model.PolicyTemplate, error) {
	if err := s.EnsureTemplatesTable(ctx); err != nil {
		// Log warning, return builtins fallback
	}

	result := append([]*model.PolicyTemplate{}, builtinTemplates...)

	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, category, description, tags, icon, content, is_custom, created_at, updated_at
		FROM policy_templates
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return result, nil
		}
		return result, nil // fallback to builtins gracefully if table query fails
	}
	defer rows.Close()

	for rows.Next() {
		var t model.PolicyTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Category, &t.Description, &t.Tags, &t.Icon, &t.Content, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt); err == nil {
			result = append(result, &t)
		}
	}

	return result, nil
}

func (s *Store) GetTemplateByID(ctx context.Context, tenantID, id string) (*model.PolicyTemplate, error) {
	for _, b := range builtinTemplates {
		if b.ID == id {
			return b, nil
		}
	}

	if err := s.EnsureTemplatesTable(ctx); err != nil {
		return nil, err
	}

	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	var t model.PolicyTemplate
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, category, description, tags, icon, content, is_custom, created_at, updated_at
		FROM policy_templates
		WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
	`, id, tenantID).Scan(&t.ID, &t.Name, &t.Category, &t.Description, &t.Tags, &t.Icon, &t.Content, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) SaveCustomTemplate(ctx context.Context, tenantID string, t *model.PolicyTemplate) error {
	if err := s.EnsureTemplatesTable(ctx); err != nil {
		return err
	}

	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	if t.Tags == nil {
		t.Tags = []string{}
	}
	if t.Icon == "" {
		t.Icon = "shield-check"
	}
	t.IsCustom = true
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now

	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_templates (id, tenant_id, name, category, description, tags, icon, content, is_custom, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			tenant_id = EXCLUDED.tenant_id,
			category = EXCLUDED.category,
			description = EXCLUDED.description,
			tags = EXCLUDED.tags,
			icon = EXCLUDED.icon,
			content = EXCLUDED.content,
			updated_at = EXCLUDED.updated_at
	`, t.ID, tenantID, t.Name, t.Category, t.Description, t.Tags, t.Icon, t.Content, true, now, now)

	return err
}

func (s *Store) DeleteCustomTemplate(ctx context.Context, tenantID, id string) error {
	if err := s.EnsureTemplatesTable(ctx); err != nil {
		return err
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM policy_templates WHERE id = $1 AND tenant_id = $2 AND is_custom = true`, id, tenantID)
	return err
}
