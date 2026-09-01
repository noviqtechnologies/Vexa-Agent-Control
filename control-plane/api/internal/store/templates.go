package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var builtinTemplates = []*model.PolicyTemplate{
	{
		ID:          "au-adv-pii",
		Name:        "Advanced PII Protection (Australia)",
		Category:    "PII Protection",
		Categories:  []string{"Australia", "PII Protection", "Regulatory", "Financial Services"},
		Complexity:  "High Complexity",
		Description: "Protects Australian-specific identifiers (TFN, Medicare, Passports), international employee data, financial information, credentials, and industry-specific sensitive data.",
		Tags:        []string{"Australia", "APRA CPS 234", "TFN", "Medicare", "Passports", "DLP"},
		Guardrails:  []string{"au-pii-tax-identifiers", "au-pii-passports", "international-pii-identifiers", "contact-information-pii", "financial-pii", "credentials-api-keys", "network-infrastructure-pii", "protected-class-information"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

llm:
  providers:
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*", "claude-3-7-sonnet*"]
      dlp_tier: "strict"
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "o3-mini*"]
      dlp_tier: "strict"
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*", "gemini-2.0-flash*"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "AU_TFN"
        action: "deny"
      - entity: "AU_MEDICARE"
        action: "deny"
      - entity: "AU_PASSPORT"
        action: "deny"
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "BANK_ACCOUNT"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "PHONE_NUMBER"
        action: "redact"
      - entity: "API_KEY"
        action: "deny"

response_scanning:
  enabled: true
  scan_level: "deep"
  patterns:
    - name: "au_tfn_regex"
      regex: "\\b\\d{3}\\s?\\d{3}\\s?\\d{3}\\b"
      action: "redact"
    - name: "au_medicare_regex"
      regex: "\\b[2-6]\\d{9}\\d?\\b"
      action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials|secrets\\.json)).*$"
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
    action: pivot_error`,
	},
	{
		ID:          "baseline-pii",
		Name:        "Baseline PII Protection",
		Category:    "PII Protection",
		Categories:  []string{"PII Protection", "Security"},
		Complexity:  "Low Complexity",
		Description: "Baseline PII protection for internal tools and testing. Focuses on credentials and high-risk identifiers only. Suitable for non-sensitive internal use.",
		Tags:        []string{"Baseline", "Credentials", "API Keys", "DLP"},
		Guardrails:  []string{"au-pii-tax-identifiers", "credentials-api-keys", "financial-pii"},
		Icon:        "shield-check",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 20

llm:
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
  dlp:
    actions:
      - entity: "API_KEY"
        action: "deny"
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"

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

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "au-nsfw-filter",
		Name:        "NSFW Content Filter (Australia)",
		Category:    "Content Safety",
		Categories:  []string{"Content Safety", "Australia", "Regulatory"},
		Complexity:  "Medium Complexity",
		Description: "Blocks profanity, sexual content, NSFW requests, self-harm content, and child safety violations using English and Australian-specific slang. Protects against inappropriate content involving Australian profanity, self-harm, and content involving minors.",
		Tags:        []string{"Content Safety", "Australia", "Profanity", "Safety", "Slang"},
		Guardrails:  []string{"nsfw-content-filter-english", "nsfw-content-filter-australian", "nsfw-self-harm-filter", "nsfw-child-safety-filter", "nsfw-racial-bias-filter"},
		Icon:        "alert-triangle",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

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
      models: ["gemini-1.5-pro*", "gemini-2.0-flash*"]
  prompt_injection:
    action: "block"
    threshold: 0.85
  jailbreak_defense:
    action: "block"
    heuristics: true

response_scanning:
  enabled: true
  scan_level: "deep"
  content_safety:
    nsfw_filter: true
    hate_speech_filter: true
    self_harm_filter: true
    regional_slang: ["en_AU", "en_US", "en_GB"]

tools:
  - name: execute_query
    action: allow
  - name: generate_report
    action: allow

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "basic-nsfw-filter",
		Name:        "NSFW Content Filter (Basic)",
		Category:    "Content Safety",
		Categories:  []string{"Content Safety"},
		Complexity:  "Low Complexity",
		Description: "Basic NSFW content filtering for English only. Blocks profanity, sexual content, slurs, solicitation, explicit content, and harassment.",
		Tags:        []string{"Content Safety", "Profanity", "English", "Toxicity"},
		Guardrails:  []string{"nsfw-content-filter-english", "nsfw-self-harm-filter", "nsfw-child-safety-filter"},
		Icon:        "alert-circle",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 20

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude*"]
    - name: "google"
      action: "allow"
      models: ["gemini*"]

response_scanning:
  enabled: true
  content_safety:
    nsfw_filter: true
    hate_speech_filter: true

firewall:
  enabled: true`,
	},
	{
		ID:          "all-regions-nsfw-filter",
		Name:        "NSFW Content Filter (All Regions)",
		Category:    "Content Safety",
		Categories:  []string{"Content Safety", "Regulatory"},
		Complexity:  "High Complexity",
		Description: "Comprehensive multi-language NSFW content filtering. Blocks profanity, sexual content, inappropriate requests, hate speech, and slurs across global multi-lingual corpuses.",
		Tags:        []string{"Content Safety", "Multi-Language", "Global", "Jailbreak"},
		Guardrails:  []string{"nsfw-content-filter-english", "nsfw-content-filter-multilingual", "nsfw-hate-speech-filter", "nsfw-self-harm-filter", "nsfw-child-safety-filter"},
		Icon:        "shield-alert",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 25

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "gpt-4o-mini*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*", "claude-3-7-sonnet*"]
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*", "gemini-2.0-flash*"]
  prompt_injection:
    action: "block"
    threshold: 0.80
  jailbreak_defense:
    action: "block"
    heuristics: true

response_scanning:
  enabled: true
  scan_level: "deep"
  content_safety:
    nsfw_filter: true
    hate_speech_filter: true
    self_harm_filter: true
    child_safety_filter: true
    languages: ["en", "es", "fr", "de", "ar", "ja", "zh"]

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
	},
	{
		ID:          "gdpr-eu-pii",
		Name:        "GDPR Art. 32 — EU PII Protection",
		Category:    "PII Protection",
		Categories:  []string{"EU", "PII Protection", "Regulatory"},
		Complexity:  "Medium Complexity",
		Description: "GDPR Article 32 compliance for EU personal data protection. Masks French national IDs (NIR/INSEE), EU Tax IDs, IBAN accounts, and national health identifiers.",
		Tags:        []string{"EU", "GDPR", "NIR/INSEE", "IBAN", "Compliance", "Tax"},
		Guardrails:  []string{"eu-gdpr-nir-insee", "eu-iban-validator", "eu-tax-identifiers", "credentials-api-keys", "contact-information-pii"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "gpt-4o-mini*"]
      dlp_tier: "strict"
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
      dlp_tier: "strict"
    - name: "google"
      action: "allow"
      models: ["gemini-1.5-pro*"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "EU_NIR_INSEE"
        action: "deny"
      - entity: "EU_TAX_ID"
        action: "deny"
      - entity: "IBAN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "PHONE_NUMBER"
        action: "redact"
      - entity: "CREDIT_CARD"
        action: "deny"

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

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "safe-cursor",
		Name:        "Safe Cursor Workstation",
		Category:    "Developer Security",
		Categories:  []string{"Developer Security", "Security"},
		Complexity:  "Medium Complexity",
		Description: "Blocks destructive shell operations (rm -rf, mkfs, dd), shields .env, id_rsa, and credentials, and stops post-read secret exfiltration.",
		Tags:        []string{"IDE", "Cursor", "Developer", "Filesystem", "Zero-Trust"},
		Guardrails:  []string{"shell-destructive-blocks", "filesystem-secret-shield", "exfiltration-sequence-guard", "model-allowlist-governance"},
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
		ID:          "pci-dss-compliance",
		Name:        "PCI-DSS & Financial Data Protection",
		Category:    "Financial Services",
		Categories:  []string{"Financial Services", "PII Protection", "Regulatory"},
		Complexity:  "High Complexity",
		Description: "Zero-tolerance financial security policy. Immediately blocks credit card numbers (Luhn validated), CVVs, and IBANs while restricting outbound egress to PCI boundaries.",
		Tags:        []string{"PCI-DSS", "Finance", "Credit Card", "DLP", "Compliance"},
		Guardrails:  []string{"financial-pci-luhn", "cvv-exp-redactor", "iban-bank-account-block", "pci-egress-boundary", "credentials-api-keys"},
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
		ID:          "hipaa-compliance",
		Name:        "HIPAA & Medical PII Protection",
		Category:    "Healthcare",
		Categories:  []string{"Healthcare", "PII Protection", "Regulatory"},
		Complexity:  "High Complexity",
		Description: "Auto-redacts PHI, SSNs, Medical Record Numbers (MRN), and PII across LLM requests and agent responses.",
		Tags:        []string{"HIPAA", "DLP", "PHI", "Healthcare", "PII"},
		Guardrails:  []string{"healthcare-phi-redactor", "mrn-identifier-block", "ssn-national-id-deny", "deep-response-scanning"},
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
		ID:          "autonomous-agent-guardrails",
		Name:        "Autonomous Agent & MCP Guardrails",
		Category:    "Production Governance",
		Categories:  []string{"Production Governance", "Security"},
		Complexity:  "High Complexity",
		Description: "Hardened sandbox for autonomous agent workflows (LangChain, AutoGPT, MCP). Enforces tool schema drift detection, cycle break prevention, and command safelists.",
		Tags:        []string{"Agents", "MCP", "Schema Drift", "Cycle Detection", "Sandbox"},
		Guardrails:  []string{"mcp-schema-drift-guard", "cycle-break-pivot-error", "tool-sandbox-safelist", "path-traversal-validator"},
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
		ID:          "canada-pipeda-guardrails",
		Name:        "PIPEDA & Canadian Privacy Shield",
		Category:    "Canada",
		Categories:  []string{"Canada", "FIPPA", "PIPEDA", "PII Protection", "Regulatory"},
		Complexity:  "Medium Complexity",
		Description: "Enforces Canadian federal PIPEDA and provincial FIPPA compliance. Auto-masks Social Insurance Numbers (SIN), provincial health numbers, and financial accounts.",
		Tags:        []string{"Canada", "PIPEDA", "FIPPA", "SIN", "DLP"},
		Guardrails:  []string{"ca-sin-identifier-deny", "ca-provincial-health-redact", "credentials-api-keys", "contact-information-pii"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

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
      - entity: "CA_SIN"
        action: "deny"
      - entity: "CA_HEALTH_NUMBER"
        action: "redact"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "CREDIT_CARD"
        action: "deny"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "singapore-pdpa-guardrails",
		Name:        "Singapore PDPA & MAS FinTech Compliance",
		Category:    "Singapore",
		Categories:  []string{"Singapore", "Financial Services", "PII Protection", "Regulatory"},
		Complexity:  "Medium Complexity",
		Description: "Enforces Singapore Personal Data Protection Act (PDPA) and MAS Cyber Hygiene guidelines. Masks NRIC/FIN numbers and restricts outbound calls to vetted endpoints.",
		Tags:        []string{"Singapore", "PDPA", "NRIC", "MAS", "FinTech"},
		Guardrails:  []string{"sg-nric-fin-redact", "mas-cyber-hygiene-egress", "credentials-api-keys", "financial-pii"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
  dlp:
    actions:
      - entity: "SG_NRIC_FIN"
        action: "deny"
      - entity: "BANK_ACCOUNT"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

tools:
  - name: http_request
    action: allow
    parameters:
      - name: url
        type: string
        required: true
        pattern: "^https://([a-zA-Z0-9-]+\\.)*(gov\\.sg|bank\\.internal)(/.*)?$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "uae-data-protection",
		Name:        "UAE Data Protection & Sovereign AI Policy",
		Category:    "UAE",
		Categories:  []string{"UAE", "PII Protection", "Regulatory"},
		Complexity:  "Medium Complexity",
		Description: "Aligns with UAE Federal Decree-Law No. 45 on Personal Data Protection and Dubai AI Ethics. Redacts Emirates ID numbers, phone numbers, and restricts data sovereignty.",
		Tags:        []string{"UAE", "Emirates ID", "Data Sovereignty", "Dubai AI", "DLP"},
		Guardrails:  []string{"uae-emirates-id-mask", "sovereign-egress-lock", "credentials-api-keys", "contact-information-pii"},
		Icon:        "shield",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]
  dlp:
    actions:
      - entity: "UAE_EMIRATES_ID"
        action: "deny"
      - entity: "PHONE_NUMBER"
        action: "redact"
      - entity: "CREDIT_CARD"
        action: "deny"

tools:
  - name: execute_query
    action: allow

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
	{
		ID:          "aviation-critical-safety",
		Name:        "Aviation & Mission-Critical Control",
		Category:    "Aviation",
		Categories:  []string{"Aviation", "Security", "Regulatory"},
		Complexity:  "High Complexity",
		Description: "Safety-critical control envelope inspired by DO-178C. Locks out unvetted shell execution, enforces deterministic token budgets, and eliminates cycle runaway.",
		Tags:        []string{"Aviation", "Safety-Critical", "Telemetry", "Lockout", "DO-178C"},
		Guardrails:  []string{"aviation-command-lockout", "deterministic-token-bucket", "cycle-break-pivot-error", "schema-drift-guard"},
		Icon:        "plane",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 5

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*"]
  prompt_injection:
    action: "block"
    threshold: 0.90

tools:
  - name: query_telemetry
    action: allow
  - name: exec_shell
    action: deny

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 1
    action: pivot_error

schema_drift:
  enabled: true
  action: block`,
	},
	{
		ID:          "brand-protection-safeguards",
		Name:        "Brand Protection & Reputational Guardrails",
		Category:    "Brand Protection",
		Categories:  []string{"Brand Protection", "Claims", "Content Safety"},
		Complexity:  "Low Complexity",
		Description: "Prevents unvetted public claims, competitive defamation, and unauthorized corporate commitments in agent responses.",
		Tags:        []string{"Brand", "PR", "Reputation", "Hallucination", "Claims"},
		Guardrails:  []string{"brand-claim-verifier", "competitor-mention-scanner", "unauthorized-commitment-filter"},
		Icon:        "sparkles",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 20

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "gpt-4o-mini*"]
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet*"]

response_scanning:
  enabled: true
  brand_safety:
    block_unauthorized_claims: true
    block_competitor_attacks: true

firewall:
  enabled: true`,
	},
	{
		ID:          "cost-governance-fallback",
		Name:        "LLM Cost Guardrails & Model Fallback",
		Category:    "Cost & Governance",
		Categories:  []string{"Cost & Governance", "Security"},
		Complexity:  "Low Complexity",
		Description: "Enforces automated model fallback to route costly requests (e.g. o1/opus) to cost-effective alternatives (gpt-4o-mini, gemini-1.5-flash) with tight rate limits.",
		Tags:        []string{"Cost", "FinOps", "Fallback", "Budget", "Rate Limiting"},
		Guardrails:  []string{"model-fallback-routing", "rate-limiting-budget", "token-throttle-cap"},
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
		ID:          "prompt-injection-jailbreak-shield",
		Name:        "Prompt Injection & Jailbreak Shield",
		Category:    "Security",
		Categories:  []string{"Security", "Content Safety", "Developer Security"},
		Complexity:  "High Complexity",
		Description: "Multi-layer defense against indirect prompt injection, DAN/jailbreak vectors, system prompt extraction, and rogue tool execution hijacking.",
		Tags:        []string{"Security", "Prompt Injection", "Jailbreak", "Red Teaming", "Zero-Trust"},
		Guardrails:  []string{"prompt-injection-heuristic", "jailbreak-pattern-detector", "system-prompt-exfiltration-guard", "tool-hijack-prevention"},
		Icon:        "shield-alert",
		IsCustom:    false,
		Content: `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

llm:
  prompt_injection:
    action: "block"
    threshold: 0.82
  jailbreak_defense:
    action: "block"
    heuristics: true
    system_prompt_shield: true

sequence_rules:
  - name: block_jailbreak_privilege_escalation
    window_size: 3
    antecedent_tools:
      - read_file
    consequent_tools:
      - exec_shell
    action: block
    message: "Security Violation: Blocked shell access attempt after suspicious system file inspection."

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
	},
}

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
	if err != nil {
		return err
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "policy_templates",
		Action:         "created",
		ChangedBy:      "admin",
		ActorRole:      "admin",
		AffectedItemID: t.ID,
		UpdatedValue: map[string]interface{}{
			"id":          t.ID,
			"name":        t.Name,
			"category":    t.Category,
			"complexity":  t.Complexity,
			"description": t.Description,
		},
		Outcome: "SUCCESS",
	})

	return nil
}

func (s *Store) DeleteCustomTemplate(ctx context.Context, tenantID, id string) error {
	if err := s.EnsureTemplatesTable(ctx); err != nil {
		return err
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM policy_templates WHERE id = $1 AND tenant_id = $2 AND is_custom = true`, id, tenantID)
	if err != nil {
		return err
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "policy_templates",
		Action:         "deleted",
		ChangedBy:      "admin",
		ActorRole:      "admin",
		AffectedItemID: id,
		UpdatedValue: map[string]interface{}{
			"id": id,
		},
		Outcome: "SUCCESS",
	})

	return nil
}
