import React, { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type PolicyTemplate } from '../api/client'
import './PolicyMarketplace.css'

export const BUILTIN_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'au-adv-pii',
    name: 'Advanced PII Protection (Australia)',
    category: 'PII Protection',
    categories: ['Australia', 'PII Protection', 'Regulatory', 'Financial Services'],
    complexity: 'High Complexity',
    description: 'Protects Australian-specific identifiers, international employee data, financial information, credentials, and industry-specific sensitive data.',
    tags: ['Australia', 'APRA CPS 234', 'TFN', 'Medicare', 'Passports', 'DLP'],
    guardrails: [
      'au-pii-tax-identifiers',
      'au-pii-passports',
      'international-pii-identifiers',
      'contact-information-pii',
      'financial-pii',
      'credentials-api-keys',
      'network-infrastructure-pii',
      'protected-class-information'
    ],
    icon: 'shield',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'baseline-pii',
    name: 'Baseline PII Protection',
    category: 'PII Protection',
    categories: ['PII Protection', 'Security'],
    complexity: 'Low Complexity',
    description: 'Baseline PII protection for internal tools and testing. Focuses on credentials and high-risk identifiers only. Suitable for non-sensitive internal use.',
    tags: ['Baseline', 'Credentials', 'API Keys', 'DLP'],
    guardrails: [
      'au-pii-tax-identifiers',
      'credentials-api-keys',
      'financial-pii'
    ],
    icon: 'shield-check',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'au-nsfw-filter',
    name: 'NSFW Content Filter (Australia)',
    category: 'Content Safety',
    categories: ['Content Safety', 'Australia', 'Regulatory'],
    complexity: 'Medium Complexity',
    description: 'Blocks profanity, sexual content, NSFW requests, self-harm content, and child safety violations using English and Australian-specific slang. Protects against inappropriate content including Australian profanity, self-harm, and content involving minors.',
    tags: ['Content Safety', 'Australia', 'Profanity', 'Safety', 'Slang'],
    guardrails: [
      'nsfw-content-filter-english',
      'nsfw-content-filter-australian',
      'nsfw-self-harm-filter',
      'nsfw-child-safety-filter',
      'nsfw-racial-bias-filter'
    ],
    icon: 'alert-triangle',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'basic-nsfw-filter',
    name: 'NSFW Content Filter (Basic)',
    category: 'Content Safety',
    categories: ['Content Safety'],
    complexity: 'Low Complexity',
    description: 'Basic NSFW content filtering for English only. Blocks profanity, sexual content, slurs, solicitation, explicit content, and harassment.',
    tags: ['Content Safety', 'Profanity', 'English', 'Toxicity'],
    guardrails: [
      'nsfw-content-filter-english',
      'nsfw-self-harm-filter',
      'nsfw-child-safety-filter'
    ],
    icon: 'alert-circle',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'all-regions-nsfw-filter',
    name: 'NSFW Content Filter (All Regions)',
    category: 'Content Safety',
    categories: ['Content Safety', 'Regulatory'],
    complexity: 'High Complexity',
    description: 'Comprehensive multi-language NSFW content filtering. Blocks profanity, sexual content, inappropriate requests, hate speech, and slurs across global multi-lingual corpuses.',
    tags: ['Content Safety', 'Multi-Language', 'Global', 'Jailbreak'],
    guardrails: [
      'nsfw-content-filter-english',
      'nsfw-content-filter-multilingual',
      'nsfw-hate-speech-filter',
      'nsfw-self-harm-filter',
      'nsfw-child-safety-filter'
    ],
    icon: 'shield-alert',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'gdpr-eu-pii',
    name: 'GDPR Art. 32 — EU PII Protection',
    category: 'PII Protection',
    categories: ['EU', 'PII Protection', 'Regulatory'],
    complexity: 'Medium Complexity',
    description: 'GDPR Article 32 compliance for EU personal data protection. Masks French national IDs (NIR/INSEE), EU Tax IDs, IBAN accounts, and national health identifiers.',
    tags: ['EU', 'GDPR', 'NIR/INSEE', 'IBAN', 'Compliance', 'Tax'],
    guardrails: [
      'eu-gdpr-nir-insee',
      'eu-iban-validator',
      'eu-tax-identifiers',
      'credentials-api-keys',
      'contact-information-pii'
    ],
    icon: 'shield',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'safe-cursor',
    name: 'Safe Cursor Workstation',
    category: 'Developer Security',
    categories: ['Developer Security', 'Security'],
    complexity: 'Medium Complexity',
    description: 'Blocks destructive shell operations (rm -rf, mkfs, dd), shields .env, id_rsa, and credentials, and stops post-read secret exfiltration.',
    tags: ['IDE', 'Cursor', 'Developer', 'Filesystem', 'Zero-Trust'],
    guardrails: [
      'shell-destructive-blocks',
      'filesystem-secret-shield',
      'exfiltration-sequence-guard',
      'model-allowlist-governance'
    ],
    icon: 'shield-check',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
        pattern: "^(?!.*(rm\\\\s+-rf|mkfs|dd\\\\s+if|chmod\\\\s+-R\\\\s+777|sudo\\\\s+rm)).*$"

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
    id: 'pci-dss-compliance',
    name: 'PCI-DSS & Financial Data Protection',
    category: 'Financial Services',
    categories: ['Financial Services', 'PII Protection', 'Regulatory'],
    complexity: 'High Complexity',
    description: 'Zero-tolerance financial security policy. Immediately blocks credit card numbers (Luhn validated), CVVs, and IBANs while restricting outbound egress to PCI boundaries.',
    tags: ['PCI-DSS', 'Finance', 'Credit Card', 'DLP', 'Compliance'],
    guardrails: [
      'financial-pci-luhn',
      'cvv-exp-redactor',
      'iban-bank-account-block',
      'pci-egress-boundary',
      'credentials-api-keys'
    ],
    icon: 'credit-card',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
        pattern: "^https://([a-zA-Z0-9-]+\\\\.)*(stripe\\\\.com|api\\\\.company\\\\.internal)(/.*)?$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
  },
  {
    id: 'hipaa-compliance',
    name: 'HIPAA & Medical PII Protection',
    category: 'Healthcare',
    categories: ['Healthcare', 'PII Protection', 'Regulatory'],
    complexity: 'High Complexity',
    description: 'Auto-redacts PHI, SSNs, Medical Record Numbers (MRN), and PII across LLM requests and agent responses.',
    tags: ['HIPAA', 'DLP', 'PHI', 'Healthcare', 'PII'],
    guardrails: [
      'healthcare-phi-redactor',
      'mrn-identifier-block',
      'ssn-national-id-deny',
      'deep-response-scanning'
    ],
    icon: 'heart-pulse',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
      regex: "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
      action: "redact"
    - name: "mrn_pattern"
      regex: "\\\\bMRN-\\\\d{6,8}\\\\b"
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
    id: 'autonomous-agent-guardrails',
    name: 'Autonomous Agent & MCP Guardrails',
    category: 'Production Governance',
    categories: ['Production Governance', 'Security'],
    complexity: 'High Complexity',
    description: 'Hardened sandbox for autonomous agent workflows (LangChain, AutoGPT, MCP). Enforces tool schema drift detection, cycle break prevention, and command safelists.',
    tags: ['Agents', 'MCP', 'Schema Drift', 'Cycle Detection', 'Sandbox'],
    guardrails: [
      'mcp-schema-drift-guard',
      'cycle-break-pivot-error',
      'tool-sandbox-safelist',
      'path-traversal-validator'
    ],
    icon: 'bot',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
        pattern: "^(?!.*(sudo|rm\\\\s+-rf|mkfs|dd|chmod|chown)).*$"

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
    id: 'canada-pipeda-guardrails',
    name: 'PIPEDA & Canadian Privacy Shield',
    category: 'Canada',
    categories: ['Canada', 'FIPPA', 'PIPEDA', 'PII Protection', 'Regulatory'],
    complexity: 'Medium Complexity',
    description: 'Enforces Canadian federal PIPEDA and provincial FIPPA compliance. Auto-masks Social Insurance Numbers (SIN), provincial health numbers, and financial accounts.',
    tags: ['Canada', 'PIPEDA', 'FIPPA', 'SIN', 'DLP'],
    guardrails: [
      'ca-sin-identifier-deny',
      'ca-provincial-health-redact',
      'credentials-api-keys',
      'contact-information-pii'
    ],
    icon: 'shield',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'singapore-pdpa-guardrails',
    name: 'Singapore PDPA & MAS FinTech Compliance',
    category: 'Singapore',
    categories: ['Singapore', 'Financial Services', 'PII Protection', 'Regulatory'],
    complexity: 'Medium Complexity',
    description: 'Enforces Singapore Personal Data Protection Act (PDPA) and MAS Cyber Hygiene guidelines. Masks NRIC/FIN numbers and restricts outbound calls to vetted endpoints.',
    tags: ['Singapore', 'PDPA', 'NRIC', 'MAS', 'FinTech'],
    guardrails: [
      'sg-nric-fin-redact',
      'mas-cyber-hygiene-egress',
      'credentials-api-keys',
      'financial-pii'
    ],
    icon: 'shield',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
        pattern: "^https://([a-zA-Z0-9-]+\\\\.)*(gov\\\\.sg|bank\\\\.internal)(/.*)?$"

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 2
    action: pivot_error`,
  },
  {
    id: 'uae-data-protection',
    name: 'UAE Data Protection & Sovereign AI Policy',
    category: 'UAE',
    categories: ['UAE', 'PII Protection', 'Regulatory'],
    complexity: 'Medium Complexity',
    description: 'Aligns with UAE Federal Decree-Law No. 45 on Personal Data Protection and Dubai AI Ethics. Redacts Emirates ID numbers, phone numbers, and restricts data sovereignty.',
    tags: ['UAE', 'Emirates ID', 'Data Sovereignty', 'Dubai AI', 'DLP'],
    guardrails: [
      'uae-emirates-id-mask',
      'sovereign-egress-lock',
      'credentials-api-keys',
      'contact-information-pii'
    ],
    icon: 'shield',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'aviation-critical-safety',
    name: 'Aviation & Mission-Critical Control',
    category: 'Aviation',
    categories: ['Aviation', 'Security', 'Regulatory'],
    complexity: 'High Complexity',
    description: 'Safety-critical control envelope inspired by DO-178C. Locks out unvetted shell execution, enforces deterministic token budgets, and eliminates cycle runaway.',
    tags: ['Aviation', 'Safety-Critical', 'Telemetry', 'Lockout', 'DO-178C'],
    guardrails: [
      'aviation-command-lockout',
      'deterministic-token-bucket',
      'cycle-break-pivot-error',
      'schema-drift-guard'
    ],
    icon: 'plane',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'brand-protection-safeguards',
    name: 'Brand Protection & Reputational Guardrails',
    category: 'Brand Protection',
    categories: ['Brand Protection', 'Claims', 'Content Safety'],
    complexity: 'Low Complexity',
    description: 'Prevents unvetted public claims, competitive defamation, and unauthorized corporate commitments in agent responses.',
    tags: ['Brand', 'PR', 'Reputation', 'Hallucination', 'Claims'],
    guardrails: [
      'brand-claim-verifier',
      'competitor-mention-scanner',
      'unauthorized-commitment-filter'
    ],
    icon: 'sparkles',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'cost-governance-fallback',
    name: 'LLM Cost Guardrails & Model Fallback',
    category: 'Cost & Governance',
    categories: ['Cost & Governance', 'Security'],
    complexity: 'Low Complexity',
    description: 'Enforces automated model fallback to route costly requests (e.g. o1/opus) to cost-effective alternatives (gpt-4o-mini, gemini-1.5-flash) with tight rate limits.',
    tags: ['Cost', 'FinOps', 'Fallback', 'Budget', 'Rate Limiting'],
    guardrails: [
      'model-fallback-routing',
      'rate-limiting-budget',
      'token-throttle-cap'
    ],
    icon: 'dollar-sign',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
    id: 'prompt-injection-jailbreak-shield',
    name: 'Prompt Injection & Jailbreak Shield',
    category: 'Security',
    categories: ['Security', 'Content Safety', 'Developer Security'],
    complexity: 'High Complexity',
    description: 'Multi-layer defense against indirect prompt injection, DAN/jailbreak vectors, system prompt extraction, and rogue tool execution hijacking.',
    tags: ['Security', 'Prompt Injection', 'Jailbreak', 'Red Teaming', 'Zero-Trust'],
    guardrails: [
      'prompt-injection-heuristic',
      'jailbreak-pattern-detector',
      'system-prompt-exfiltration-guard',
      'tool-hijack-prevention'
    ],
    icon: 'shield-alert',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2"
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
]

// Ordered canonical categories for the sidebar filter
const SIDEBAR_CATEGORIES = [
  'Australia',
  'Aviation',
  'Brand Protection',
  'Canada',
  'Claims',
  'Content Safety',
  'Cost & Governance',
  'Developer Security',
  'EU',
  'Financial Services',
  'FIPPA',
  'Healthcare',
  'PII Protection',
  'PIPEDA',
  'Production Governance',
  'Regulatory',
  'Security',
  'Singapore',
  'UAE',
]

export default function PolicyMarketplace() {
  const [templates, setTemplates] = useState<PolicyTemplate[]>(BUILTIN_TEMPLATES)
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategories, setSelectedCategories] = useState<string[]>([])
  const [selectedComplexity, setSelectedComplexity] = useState<string>('All')
  
  // Modals state
  const [previewTemplate, setPreviewTemplate] = useState<PolicyTemplate | null>(null)
  const [selectedActionTemplate, setSelectedActionTemplate] = useState<PolicyTemplate | null>(null)
  const [showAiModal, setShowAiModal] = useState(false)
  const [aiQuery, setAiQuery] = useState('')
  const [aiResults, setAiResults] = useState<{ template: PolicyTemplate; score: number; reasons: string[] }[] | null>(null)
  const [aiAnalyzing, setAiAnalyzing] = useState(false)

  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [applyingId, setApplyingId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Custom Template Creation Modal State
  const [showCustomModal, setShowCustomModal] = useState(false)
  const [customName, setCustomName] = useState('')
  const [customCategory, setCustomCategory] = useState('Developer Security')
  const [customComplexity, setCustomComplexity] = useState('Medium Complexity')
  const [customDesc, setCustomDesc] = useState('')
  const [customGuardrails, setCustomGuardrails] = useState('')
  const [customYaml, setCustomYaml] = useState('')
  const [savingCustom, setSavingCustom] = useState(false)

  const navigate = useNavigate()

  useEffect(() => {
    fetchTemplates()
  }, [])

  const fetchTemplates = async () => {
    try {
      setLoading(true)
      const list = await api.listTemplates()
      if (Array.isArray(list) && list.length > 0) {
        // Merge list with builtin templates, matching on ID
        const serverIds = new Set(list.map(t => t.id))
        const unlistedBuiltins = BUILTIN_TEMPLATES.filter(b => !serverIds.has(b.id))
        
        // Enrich server templates with builtin defaults if missing fields
        const enriched = list.map(item => {
          const builtinMatch = BUILTIN_TEMPLATES.find(b => b.id === item.id)
          return {
            ...item,
            categories: item.categories || builtinMatch?.categories || [item.category],
            complexity: item.complexity || builtinMatch?.complexity || 'Medium Complexity',
            guardrails: item.guardrails || builtinMatch?.guardrails || []
          }
        })
        setTemplates([...enriched, ...unlistedBuiltins])
      } else {
        setTemplates(BUILTIN_TEMPLATES)
      }
    } catch {
      setTemplates(BUILTIN_TEMPLATES)
    } finally {
      setLoading(false)
    }
  }

  // Calculate dynamic counts for each category
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    SIDEBAR_CATEGORIES.forEach(cat => {
      counts[cat] = 0
    })

    templates.forEach(t => {
      const templateCats = new Set<string>()
      if (t.category) templateCats.add(t.category)
      if (Array.isArray(t.categories)) {
        t.categories.forEach(c => templateCats.add(c))
      }
      if (Array.isArray(t.tags)) {
        t.tags.forEach(tag => templateCats.add(tag))
      }

      SIDEBAR_CATEGORIES.forEach(cat => {
        if (templateCats.has(cat) || Array.from(templateCats).some(tc => tc.toLowerCase() === cat.toLowerCase())) {
          counts[cat] = (counts[cat] || 0) + 1
        }
      })
    })

    return counts
  }, [templates])

  const toggleCategory = (cat: string) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    )
  }

  const clearAllCategories = () => {
    setSelectedCategories([])
  }

  // Filter templates based on Search, Multi-Select Categories, and Complexity
  const filteredTemplates = useMemo(() => {
    return (Array.isArray(templates) ? templates : []).filter(t => {
      if (!t) return false
      const name = t.name || ''
      const desc = t.description || ''
      const tags = Array.isArray(t.tags) ? t.tags : []
      const guardrails = Array.isArray(t.guardrails) ? t.guardrails : []
      const templateCats = [t.category, ...(t.categories || []), ...tags].filter(Boolean)

      // Category filter (if any selected, template must match at least one)
      let matchesCategory = true
      if (selectedCategories.length > 0) {
        matchesCategory = selectedCategories.some(selectedCat =>
          templateCats.some(tc => tc.toLowerCase() === selectedCat.toLowerCase())
        )
      }

      // Complexity filter
      let matchesComplexity = true
      if (selectedComplexity !== 'All') {
        matchesComplexity = (t.complexity || '').toLowerCase().includes(selectedComplexity.toLowerCase())
      }

      // Search filter
      const q = searchQuery.toLowerCase().trim()
      let matchesSearch = true
      if (q) {
        matchesSearch =
          name.toLowerCase().includes(q) ||
          desc.toLowerCase().includes(q) ||
          tags.some(tag => (tag || '').toLowerCase().includes(q)) ||
          guardrails.some(g => (g || '').toLowerCase().includes(q)) ||
          templateCats.some(c => (c || '').toLowerCase().includes(q))
      }

      return matchesCategory && matchesComplexity && matchesSearch
    })
  }, [templates, selectedCategories, selectedComplexity, searchQuery])

  const handleApplyTemplate = async (template: PolicyTemplate) => {
    if (!template) return
    try {
      setApplyingId(template.id)
      setMessage(null)
      const version = `v-${template.id}-${Date.now().toString().slice(-4)}`
      await api.savePolicy({
        version,
        content: template.content || '',
        is_active: true
      })
      setMessage({
        type: 'success',
        text: `Successfully applied "${template.name || template.id}" posture to fleet! Active policy updated.`
      })
      setTimeout(() => setMessage(null), 5000)
    } catch (err: any) {
      setMessage({ type: 'error', text: `Failed to apply template: ${err?.message || 'Unknown error'}` })
    } finally {
      setApplyingId(null)
      if (previewTemplate) setPreviewTemplate(null)
      if (selectedActionTemplate) setSelectedActionTemplate(null)
    }
  }

  const handleOpenInEditor = (template: PolicyTemplate) => {
    try {
      sessionStorage.setItem('preloaded_policy_yaml', template.content || '')
      sessionStorage.setItem('preloaded_policy_name', template.name || '')
    } catch {
      // ignore
    }
    navigate('/policy/edit')
  }

  const handleCopyYaml = (template: PolicyTemplate) => {
    navigator.clipboard.writeText(template.content || '')
    setCopiedId(template.id)
    setTimeout(() => setCopiedId(null), 2500)
  }

  // AI Recommendation Engine
  const handleRunAiRecommendation = (queryToUse?: string) => {
    const q = (queryToUse !== undefined ? queryToUse : aiQuery).toLowerCase().trim()
    if (!q) return

    const scored = (templates && templates.length > 0 ? templates : BUILTIN_TEMPLATES).map(tpl => {
      let score = 0
      const reasons: string[] = []
      const tplName = (tpl.name || '').toLowerCase()
      const tplDesc = (tpl.description || '').toLowerCase()
      const tplContent = (tpl.content || '').toLowerCase()
      const tplTags = (tpl.tags || []).map(t => t.toLowerCase())
      const tplGuardrails = (tpl.guardrails || []).map(g => g.toLowerCase())
      const tplCats = (tpl.categories || [tpl.category]).map(c => c.toLowerCase())

      // Keyword checking
      const words = q.split(/\s+/).filter(w => w.length > 2)
      words.forEach(w => {
        if (tplName.includes(w)) { score += 25; reasons.push(`Direct title match on "${w}"`) }
        if (tplDesc.includes(w)) { score += 15; reasons.push(`Matches security intent for "${w}"`) }
        if (tplTags.includes(w)) { score += 20; reasons.push(`Tagged with #${w}`) }
        if (tplCats.includes(w)) { score += 20; reasons.push(`Direct category match in ${w}`) }
        if (tplGuardrails.some(g => g.includes(w))) { score += 25; reasons.push(`Includes guardrail "${w}"`) }
        if (tplContent.includes(w)) { score += 10 }
      })

      // Jurisdiction and domain boosts
      if (q.includes('australia') || q.includes('tfn') || q.includes('medicare') || q.includes('apra')) {
        if (tplCats.includes('australia')) { score += 40; reasons.push('Complies with Australian APRA CPS 234 & Privacy standards') }
      }
      if (q.includes('cursor') || q.includes('ide') || q.includes('developer') || q.includes('shell') || q.includes('rm -rf') || q.includes('.env')) {
        if (tpl.id === 'safe-cursor' || tplCats.includes('developer security')) {
          score += 50
          reasons.push('Enforces zero-trust workstation shielding and blocks rm -rf/.env exfiltration')
        }
      }
      if (q.includes('mcp') || q.includes('agent') || q.includes('drift') || q.includes('cycle') || q.includes('sandbox')) {
        if (tpl.id === 'autonomous-agent-guardrails' || tplCats.includes('production governance')) {
          score += 50
          reasons.push('Enforces Model Context Protocol (MCP) tool schema drift locking & cycle break')
        }
      }
      if (q.includes('pci') || q.includes('credit card') || q.includes('card') || q.includes('financial') || q.includes('bank')) {
        if (tpl.id === 'pci-dss-compliance' || tplCats.includes('financial services')) {
          score += 45
          reasons.push('Luhn verification on credit cards, CVV masking & PCI egress boundaries')
        }
      }
      if (q.includes('hipaa') || q.includes('medical') || q.includes('health') || q.includes('phi') || q.includes('mrn')) {
        if (tpl.id === 'hipaa-compliance' || tplCats.includes('healthcare')) {
          score += 50
          reasons.push('Auto-redacts PHI, MRN medical identifiers, and SSNs')
        }
      }
      if (q.includes('gdpr') || q.includes('europe') || q.includes('eu') || q.includes('nir') || q.includes('insee')) {
        if (tpl.id === 'gdpr-eu-pii' || tplCats.includes('eu')) {
          score += 45
          reasons.push('GDPR Article 32 personal data masking & French NIR/INSEE protection')
        }
      }
      if (q.includes('injection') || q.includes('jailbreak') || q.includes('dan') || q.includes('prompt')) {
        if (tpl.id === 'prompt-injection-jailbreak-shield' || tpl.id === 'all-regions-nsfw-filter') {
          score += 45
          reasons.push('Multi-layer prompt injection heuristics & DAN jailbreak pattern defense')
        }
      }
      if (q.includes('cost') || q.includes('budget') || q.includes('fallback') || q.includes('rate limit')) {
        if (tpl.id === 'cost-governance-fallback') {
          score += 50
          reasons.push('Smart model fallback routing and strict token budget enforcement')
        }
      }

      // Deduplicate reasons
      const uniqueReasons = Array.from(new Set(reasons)).slice(0, 3)
      if (uniqueReasons.length === 0) {
        uniqueReasons.push('General security compatibility and policy guardrail coverage')
      }

      return {
        template: tpl,
        score: Math.min(99, Math.max(20, score + 15)),
        reasons: uniqueReasons
      }
    })

    scored.sort((a, b) => b.score - a.score)
    setAiResults(scored.slice(0, 3))
    setAiAnalyzing(false)
  }

  const handleCreateCustom = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!customName || !customYaml) return

    try {
      setSavingCustom(true)
      const id = customName.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + Date.now().toString().slice(-4)
      const guardrailsList = customGuardrails
        .split(',')
        .map(g => g.trim())
        .filter(Boolean)

      await api.createCustomTemplate({
        id,
        name: customName,
        category: customCategory,
        categories: ['Custom', customCategory],
        complexity: customComplexity,
        description: customDesc,
        tags: ['Custom', customCategory],
        guardrails: guardrailsList.length > 0 ? guardrailsList : ['custom-security-guardrail'],
        icon: 'shield',
        content: customYaml
      })
      setShowCustomModal(false)
      setCustomName('')
      setCustomDesc('')
      setCustomGuardrails('')
      setCustomYaml('')
      setMessage({ type: 'success', text: 'Custom team template saved to marketplace!' })
      fetchTemplates()
    } catch (err: any) {
      setMessage({ type: 'error', text: `Failed to save custom template: ${err?.message || 'Unknown error'}` })
    } finally {
      setSavingCustom(false)
    }
  }

  const getComplexityClass = (complexity = '') => {
    if (complexity.includes('High')) return 'complexity-high'
    if (complexity.includes('Medium')) return 'complexity-medium'
    return 'complexity-low'
  }

  const getIconElement = (icon = '', category = '') => {
    if (icon === 'plane' || category === 'Aviation') return '✈️'
    if (icon === 'heart-pulse' || category === 'Healthcare') return '🩺'
    if (icon === 'credit-card' || category === 'Financial Services') return '💳'
    if (icon === 'bot' || category === 'Production Governance') return '🤖'
    if (icon === 'dollar-sign' || category === 'Cost & Governance') return '💲'
    if (icon === 'sparkles' || category === 'Brand Protection') return '✨'
    if (icon === 'alert-triangle' || icon === 'alert-circle' || category === 'Content Safety') return '⚠️'
    if (icon === 'shield-alert') return '🛑'
    if (icon === 'shield-check') return '🛡️'
    return '🛡️'
  }

  const getIconBgClass = (icon = '', category = '', complexity = '') => {
    if (category === 'Content Safety' || icon.includes('alert')) return 'icon-bg-red'
    if (complexity.includes('High') || category === 'Healthcare' || category === 'Australia') return 'icon-bg-purple'
    if (category === 'Financial Services' || category === 'Cost & Governance') return 'icon-bg-emerald'
    return 'icon-bg-blue'
  }

  return (
    <div className="marketplace-container">
      {/* Top Header */}
      <header className="marketplace-header">
        <div className="marketplace-title-section">
          <h1>Policy Templates</h1>
          <p>Start with a pre-configured policy template to quickly set up guardrails for your organization.</p>
        </div>
        <div className="marketplace-header-actions">
          <button
            id="btn-use-ai-finder"
            className="btn-ai-finder"
            onClick={() => {
              setShowAiModal(true)
              if (!aiResults && aiQuery) handleRunAiRecommendation()
            }}
          >
            ✨ Use AI to find templates
          </button>
          <button
            id="btn-create-custom-template"
            className="btn-secondary-action"
            onClick={() => setShowCustomModal(true)}
          >
            + Save Custom Template
          </button>
          <button
            id="btn-open-editor"
            className="btn-secondary-action"
            onClick={() => navigate('/policy/edit')}
          >
            Open YAML Editor
          </button>
        </div>
      </header>

      {message && (
        <div className={`message-banner ${message.type}`} style={{ marginBottom: 20 }}>
          {message.text}
        </div>
      )}

      {/* Top Filter & Search Bar */}
      <div className="marketplace-top-controls">
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input
            id="marketplace-search-input"
            type="text"
            placeholder="Search templates by posture, guardrail, region, tags, or rules..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-search-btn" onClick={() => setSearchQuery('')}>✕</button>
          )}
        </div>

        <div className="complexity-filter-group">
          <span className="complexity-label">Complexity:</span>
          {['All', 'Low', 'Medium', 'High'].map(lvl => (
            <button
              key={lvl}
              id={`complexity-btn-${lvl.toLowerCase()}`}
              className={`complexity-btn ${selectedComplexity === lvl ? 'active' : ''}`}
              onClick={() => setSelectedComplexity(lvl)}
            >
              {lvl === 'All' ? 'All Levels' : `${lvl} Complexity`}
            </button>
          ))}
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="marketplace-main-layout">
        {/* Left Sidebar: Categories with Counts */}
        <aside className="marketplace-sidebar">
          <div className="sidebar-header">
            <h3>Categories</h3>
            {selectedCategories.length > 0 && (
              <button className="clear-link" onClick={clearAllCategories}>
                Clear ({selectedCategories.length})
              </button>
            )}
          </div>

          <div className="sidebar-category-list">
            {SIDEBAR_CATEGORIES.map(cat => {
              const count = categoryCounts[cat] || 0
              const isChecked = selectedCategories.includes(cat)

              return (
                <label
                  key={cat}
                  className={`category-checkbox-item ${isChecked ? 'selected' : ''}`}
                  id={`cat-checkbox-${cat.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleCategory(cat)}
                  />
                  <span className="category-name">{cat}</span>
                  <span className="category-count">{count}</span>
                </label>
              )
            })}
          </div>
        </aside>

        {/* Right Content Area: Template Cards Grid */}
        <main className="marketplace-content">
          <div className="results-meta-bar">
            <span>Showing <strong>{filteredTemplates.length}</strong> template{filteredTemplates.length === 1 ? '' : 's'}</span>
            {selectedCategories.length > 0 && (
              <div className="active-filter-pills">
                {selectedCategories.map(c => (
                  <span key={c} className="active-filter-pill">
                    {c} <button onClick={() => toggleCategory(c)}>✕</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {loading ? (
            <div className="loading-state">
              <div className="spinner" />
              <p>Loading security posture templates...</p>
            </div>
          ) : filteredTemplates.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <h3>No templates found</h3>
              <p>No policy templates matched your active category filters or search query.</p>
              <button className="btn-secondary-action" onClick={() => { setSearchQuery(''); clearAllCategories(); setSelectedComplexity('All') }}>
                Reset All Filters
              </button>
            </div>
          ) : (
            <div className="templates-grid">
              {filteredTemplates.map(tpl => (
                <div key={tpl.id} className="template-card" id={`template-card-${tpl.id}`}>
                  {/* Top Row: Icon Box + Complexity Pill */}
                  <div className="template-card-top">
                    <div className={`template-icon-container ${getIconBgClass(tpl.icon, tpl.category, tpl.complexity)}`}>
                      <span className="template-icon">{getIconElement(tpl.icon, tpl.category)}</span>
                    </div>
                    <span className={`complexity-badge ${getComplexityClass(tpl.complexity)}`}>
                      {tpl.complexity || 'Medium Complexity'}
                    </span>
                  </div>

                  {/* Title & Description */}
                  <h3 className="template-title">{tpl.name}</h3>
                  <p className="template-desc">{tpl.description}</p>

                  {/* Category / Region Badges */}
                  <div className="template-categories-row">
                    {(tpl.categories || [tpl.category]).slice(0, 2).map((cat, idx) => (
                      <span key={idx} className="category-pill-tag">
                        {cat}
                      </span>
                    ))}
                    {tpl.is_custom && <span className="category-pill-tag custom-tag">Custom</span>}
                  </div>

                  {/* Included Guardrails Section */}
                  <div className="included-guardrails-section">
                    <span className="included-guardrails-label">INCLUDED GUARDRAILS</span>
                    <div className="guardrails-list">
                      {(tpl.guardrails && tpl.guardrails.length > 0
                        ? tpl.guardrails
                        : ['general-policy-enforcement']
                      ).slice(0, 8).map((guard, gIdx) => (
                        <span key={gIdx} className="guardrail-pill" title={guard}>
                          {guard}
                        </span>
                      ))}
                      {(tpl.guardrails?.length || 0) > 8 && (
                        <span className="guardrail-pill-more">
                          +{(tpl.guardrails?.length || 0) - 8} more
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Card Actions */}
                  <div className="template-actions">
                    <button
                      id={`btn-use-template-${tpl.id}`}
                      className="btn-use-template"
                      onClick={() => setSelectedActionTemplate(tpl)}
                    >
                      Use Template
                    </button>
                    <button
                      id={`btn-preview-${tpl.id}`}
                      className="btn-preview-subtle"
                      onClick={() => setPreviewTemplate(tpl)}
                      title="Preview YAML"
                    >
                      YAML
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </main>
      </div>

      {/* "Use Template" Action Modal */}
      {selectedActionTemplate && (
        <div className="modal-overlay" onClick={() => setSelectedActionTemplate(null)}>
          <div className="modal-card use-template-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div className={`template-icon-container ${getIconBgClass(selectedActionTemplate.icon, selectedActionTemplate.category, selectedActionTemplate.complexity)}`}>
                  <span className="template-icon">{getIconElement(selectedActionTemplate.icon, selectedActionTemplate.category)}</span>
                </div>
                <div>
                  <h2>{selectedActionTemplate.name}</h2>
                  <span className={`complexity-badge ${getComplexityClass(selectedActionTemplate.complexity)}`}>
                    {selectedActionTemplate.complexity || 'Medium Complexity'}
                  </span>
                </div>
              </div>
              <button className="close-btn" onClick={() => setSelectedActionTemplate(null)}>✕</button>
            </div>

            <div className="modal-body">
              <p style={{ color: '#cbd5e1', fontSize: 14, marginBottom: 16, lineHeight: 1.6 }}>
                {selectedActionTemplate.description}
              </p>

              <div className="guardrails-summary-box">
                <h4>Included Guardrails & Rule Enforcements ({selectedActionTemplate.guardrails?.length || 0}):</h4>
                <div className="guardrails-list" style={{ marginTop: 8 }}>
                  {(selectedActionTemplate.guardrails || []).map((g, idx) => (
                    <span key={idx} className="guardrail-pill">
                      ✓ {g}
                    </span>
                  ))}
                </div>
              </div>

              <div className="use-template-options">
                <div
                  className="option-box primary-option"
                  onClick={() => handleApplyTemplate(selectedActionTemplate)}
                >
                  <div className="option-title">🚀 Apply Immediately to Active Fleet</div>
                  <div className="option-sub">
                    Instantly deploys this posture version to the gateway and enforces all included guardrails.
                  </div>
                  <button
                    className="btn-apply"
                    style={{ marginTop: 12 }}
                    disabled={applyingId === selectedActionTemplate.id}
                  >
                    {applyingId === selectedActionTemplate.id ? 'Deploying Posture...' : 'Deploy Active Posture'}
                  </button>
                </div>

                <div
                  className="option-box"
                  onClick={() => handleOpenInEditor(selectedActionTemplate)}
                >
                  <div className="option-title">✏️ Customize in Policy Editor</div>
                  <div className="option-sub">
                    Pre-loads this template into the YAML editor to adjust parameters, validators, or rate limits before activating.
                  </div>
                  <button
                    className="btn-preview-subtle"
                    style={{ marginTop: 12, width: '100%' }}
                    onClick={(e) => { e.stopPropagation(); handleOpenInEditor(selectedActionTemplate) }}
                  >
                    Open in Editor
                  </button>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button
                className="btn-preview"
                onClick={() => handleCopyYaml(selectedActionTemplate)}
              >
                {copiedId === selectedActionTemplate.id ? '✓ Copied YAML!' : 'Copy YAML'}
              </button>
              <button
                className="btn-preview"
                onClick={() => {
                  const t = selectedActionTemplate
                  setSelectedActionTemplate(null)
                  setPreviewTemplate(t)
                }}
              >
                View Raw YAML
              </button>
            </div>
          </div>
        </div>
      )}

      {/* "✨ Use AI to find templates" Modal */}
      {showAiModal && (
        <div className="modal-overlay" onClick={() => setShowAiModal(false)}>
          <div className="modal-card ai-finder-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 24 }}>✨</span>
                <div>
                  <h2>AI Policy Template Finder</h2>
                  <span style={{ fontSize: 13, color: '#94a3b8' }}>
                    Describe your organization's compliance requirements, tech stack, or security goals.
                  </span>
                </div>
              </div>
              <button className="close-btn" onClick={() => setShowAiModal(false)}>✕</button>
            </div>

            <div className="modal-body">
              <div className="ai-input-section">
                <textarea
                  id="ai-prompt-input"
                  className="ai-prompt-box"
                  rows={3}
                  placeholder="e.g. We are an Australian fintech handling banking records and employee data. We need to block TFN and Medicare leaks while securing Claude IDE agents from shell hazards..."
                  value={aiQuery}
                  onChange={e => setAiQuery(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault()
                      handleRunAiRecommendation()
                    }
                  }}
                />

                <div className="ai-presets-row">
                  <span className="preset-label">Quick Prompts:</span>
                  <button
                    id="preset-australia-tfn"
                    className="preset-pill"
                    onClick={() => {
                      const p = 'Australian Banking & Tax Compliance with TFN, Medicare, and APRA CPS 234'
                      setAiQuery(p)
                      handleRunAiRecommendation(p)
                    }}
                  >
                    🇦🇺 Australia TFN & Banking
                  </button>
                  <button
                    className="preset-pill"
                    onClick={() => {
                      const p = 'Cursor & Cline Developer Sandbox blocking rm -rf and .env credentials'
                      setAiQuery(p)
                      handleRunAiRecommendation(p)
                    }}
                  >
                    💻 Safe Cursor Developer Sandbox
                  </button>
                  <button
                    className="preset-pill"
                    onClick={() => {
                      const p = 'EU GDPR Art. 32 personal data masking, IBAN, and NIR French ID protection'
                      setAiQuery(p)
                      handleRunAiRecommendation(p)
                    }}
                  >
                    🇪🇺 EU GDPR Data Masking
                  </button>
                  <button
                    className="preset-pill"
                    onClick={() => {
                      const p = 'Healthcare clinic HIPAA compliance with MRN and patient PHI redaction'
                      setAiQuery(p)
                      handleRunAiRecommendation(p)
                    }}
                  >
                    🏥 HIPAA PHI Medical
                  </button>
                  <button
                    className="preset-pill"
                    onClick={() => {
                      const p = 'Autonomous LangChain & MCP tool schema drift and cycle break defense'
                      setAiQuery(p)
                      handleRunAiRecommendation(p)
                    }}
                  >
                    🤖 MCP Autonomous Sandbox
                  </button>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
                  <button
                    id="btn-ai-recommend"
                    className="btn-ai-finder"
                    disabled={!aiQuery.trim() || aiAnalyzing}
                    onClick={() => handleRunAiRecommendation()}
                  >
                    {aiAnalyzing ? 'Analyzing Security Postures...' : '✨ Find Matching Templates'}
                  </button>
                </div>
              </div>

              {/* AI Results */}
              {aiResults && (
                <div className="ai-results-section">
                  <h4 style={{ color: '#f8fafc', marginBottom: 12, fontSize: 14 }}>
                    Top Recommended Postures:
                  </h4>
                  <div className="ai-results-list">
                    {aiResults.map(({ template: tpl, score, reasons }) => (
                      <div key={tpl.id} className="ai-result-card">
                        <div className="ai-result-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div className={`template-icon-container small ${getIconBgClass(tpl.icon, tpl.category, tpl.complexity)}`}>
                              <span className="template-icon">{getIconElement(tpl.icon, tpl.category)}</span>
                            </div>
                            <div>
                              <h3 className="template-title" style={{ fontSize: 16, margin: 0 }}>{tpl.name}</h3>
                              <span style={{ fontSize: 12, color: '#94a3b8' }}>{tpl.category}</span>
                            </div>
                          </div>
                          <div className="match-score-badge">
                            {score}% Match
                          </div>
                        </div>

                        <p style={{ fontSize: 13, color: '#cbd5e1', margin: '10px 0' }}>{tpl.description}</p>

                        <div className="ai-reasons-list">
                          {reasons.map((r, rIdx) => (
                            <span key={rIdx} className="ai-reason-item">
                              ✓ {r}
                            </span>
                          ))}
                        </div>

                        <div className="ai-card-actions">
                          <button
                            className="btn-preview-subtle"
                            onClick={() => {
                              setShowAiModal(false)
                              setPreviewTemplate(tpl)
                            }}
                          >
                            Preview YAML
                          </button>
                          <button
                            className="btn-apply"
                            style={{ padding: '8px 16px' }}
                            onClick={() => {
                              setShowAiModal(false)
                              handleApplyTemplate(tpl)
                            }}
                          >
                            Use This Posture
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Preview YAML Modal */}
      {previewTemplate && (
        <div className="modal-overlay" onClick={() => setPreviewTemplate(null)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div className={`template-icon-container ${getIconBgClass(previewTemplate.icon, previewTemplate.category, previewTemplate.complexity)}`}>
                  <span className="template-icon">{getIconElement(previewTemplate.icon, previewTemplate.category)}</span>
                </div>
                <div>
                  <h2>{previewTemplate.name}</h2>
                  <span className={`complexity-badge ${getComplexityClass(previewTemplate.complexity)}`}>
                    {previewTemplate.complexity || 'Medium Complexity'}
                  </span>
                </div>
              </div>
              <button className="close-btn" onClick={() => setPreviewTemplate(null)}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ color: '#cbd5e1', fontSize: 14, marginBottom: 16 }}>{previewTemplate.description}</p>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h4 style={{ color: '#f8fafc', margin: 0, fontSize: 13 }}>Agent Control Policy Configuration (YAML):</h4>
                <button
                  className="btn-preview-subtle"
                  style={{ padding: '4px 10px', fontSize: 12 }}
                  onClick={() => handleCopyYaml(previewTemplate)}
                >
                  {copiedId === previewTemplate.id ? '✓ Copied!' : 'Copy YAML'}
                </button>
              </div>
              <pre className="yaml-viewer">{previewTemplate.content}</pre>
            </div>
            <div className="modal-footer">
              <button className="btn-preview" onClick={() => setPreviewTemplate(null)}>Close</button>
              <button
                className="btn-preview"
                onClick={() => {
                  const t = previewTemplate
                  setPreviewTemplate(null)
                  handleOpenInEditor(t)
                }}
              >
                Open in Policy Editor
              </button>
              <button
                className="btn-apply"
                disabled={applyingId === previewTemplate.id}
                onClick={() => handleApplyTemplate(previewTemplate)}
              >
                {applyingId === previewTemplate.id ? 'Applying...' : 'Apply This Posture'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Custom Template Modal */}
      {showCustomModal && (
        <div className="modal-overlay" onClick={() => setShowCustomModal(false)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <form onSubmit={handleCreateCustom}>
              <div className="modal-header">
                <h2>Save Custom Team Template</h2>
                <button className="close-btn" type="button" onClick={() => setShowCustomModal(false)}>✕</button>
              </div>
              <div className="modal-body">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Template Name</label>
                    <input
                      id="custom-template-name-input"
                      type="text"
                      required
                      placeholder="e.g. Finance Team Strict Workstation"
                      value={customName}
                      onChange={e => setCustomName(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div>
                      <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Category</label>
                      <select
                        id="custom-template-category-select"
                        value={customCategory}
                        onChange={e => setCustomCategory(e.target.value)}
                        style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                      >
                        {SIDEBAR_CATEGORIES.map(cat => (
                          <option key={cat} value={cat}>{cat}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Complexity</label>
                      <select
                        id="custom-template-complexity-select"
                        value={customComplexity}
                        onChange={e => setCustomComplexity(e.target.value)}
                        style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                      >
                        <option value="Low Complexity">Low Complexity</option>
                        <option value="Medium Complexity">Medium Complexity</option>
                        <option value="High Complexity">High Complexity</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Description</label>
                    <input
                      id="custom-template-desc-input"
                      type="text"
                      placeholder="Brief description of security rules..."
                      value={customDesc}
                      onChange={e => setCustomDesc(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Included Guardrails (comma separated)</label>
                    <input
                      id="custom-template-guardrails-input"
                      type="text"
                      placeholder="e.g. au-pii-tax-identifiers, credentials-api-keys, shell-destructive-blocks"
                      value={customGuardrails}
                      onChange={e => setCustomGuardrails(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Agent Control Policy YAML Configuration</label>
                    <textarea
                      id="custom-template-yaml-textarea"
                      required
                      rows={10}
                      placeholder={`version: "2"\ndefault_action: deny\n\nsession:\n  max_calls_per_second: 15\n\nllm:\n  dlp:\n    actions:\n      - entity: "API_KEY"\n        action: "deny"\n\nfirewall:\n  enabled: true`}
                      value={customYaml}
                      onChange={e => setCustomYaml(e.target.value)}
                      style={{ width: '100%', padding: '12px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#38bdf8', fontFamily: 'monospace', fontSize: 13 }}
                    />
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn-preview" onClick={() => setShowCustomModal(false)}>Cancel</button>
                <button type="submit" className="btn-apply" disabled={savingCustom}>
                  {savingCustom ? 'Saving...' : 'Save Template'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
