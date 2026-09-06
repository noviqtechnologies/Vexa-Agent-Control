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
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"

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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    # Frontier & Latest Generation
    - "claude-fable-5*"
    - "claude-fable-5-1*"
    - "claude-sonnet-5*"
    - "claude-opus-5*"
    - "claude-haiku-4-5*"
    - "gpt-6-astra*"
    - "gpt-5*"
    - "o3*"
    - "o4-mini*"
    - "gemini-3.8-flash*"
    - "gemini-3.8-flash-cyber*"
    - "gemini-2.5-pro*"
    - "gemini-2.5-flash*"
    - "deepseek-v4-pro*"
    - "deepseek-v4-flash*"
    # Supported Previous Generations
    - "claude-3-7-sonnet*"
    - "claude-3-5-sonnet*"
    - "claude-3-5-haiku*"
    - "gpt-4o*"
    - "gpt-4o-mini*"
    - "o1*"
    - "o3-mini*"
    - "gemini-2.0-flash*"
    - "gemini-1.5-pro*"
    - "deepseek-chat*"
    - "deepseek-reasoner*"
  providers:
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"

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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
      dlp_tier: "strict"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"

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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
      dlp_tier: "strict"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
      dlp_tier: "strict"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
      dlp_tier: "strict"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"

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
    # High-efficiency fallback tier
    - "gpt-4o-mini"
    - "o4-mini"
    - "claude-haiku-4-5"
    - "claude-3-5-haiku"
    - "gemini-3.8-flash"
    - "gemini-2.5-flash"
    - "gemini-2.0-flash"
    - "deepseek-v4-flash"
    - "deepseek-chat"
  providers:
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"

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
  providers:
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
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

interface DomainFilter {
  id: string
  label: string
  icon: string
  matchCats?: string[]
  matchIds?: string[]
}

const DOMAIN_FILTERS: DomainFilter[] = [
  { id: 'all', label: 'All Postures', icon: '🌐' },
  { id: 'pii', label: 'Data & PII Privacy', icon: '🛡️', matchCats: ['PII Protection', 'Australia', 'EU', 'Canada', 'FIPPA', 'PIPEDA', 'Healthcare', 'Singapore'] },
  { id: 'developer', label: 'IDE & Agent Sandbox', icon: '💻', matchCats: ['Developer Security'], matchIds: ['safe-cursor'] },
  { id: 'autonomous', label: 'Autonomous & MCP Tools', icon: '🤖', matchCats: ['Production Governance'], matchIds: ['autonomous-agent-guardrails'] },
  { id: 'regulatory', label: 'Regulatory & Standards', icon: '🏛️', matchCats: ['Regulatory', 'Financial Services', 'Singapore', 'UAE', 'Australia', 'Aviation', 'Claims'] },
  { id: 'safety', label: 'Threat & Content Safety', icon: '⚡', matchCats: ['Content Safety'], matchIds: ['prompt-injection-jailbreak-shield', 'all-regions-nsfw-filter', 'basic-nsfw-filter', 'au-nsfw-filter'] },
  { id: 'governance', label: 'Cost & Token Routing', icon: '💰', matchCats: ['Cost & Governance'], matchIds: ['cost-governance-fallback'] },
  { id: 'custom', label: 'Custom Team Postures', icon: '🏢', matchCats: ['Custom'] },
]

const QUICK_PRESETS = [
  { label: '🇦🇺 Australia APRA & TFN', query: 'Australia', category: 'Australia' },
  { label: '💻 Safe Cursor Workstation', query: 'Cursor', category: 'Developer Security' },
  { label: '🏥 HIPAA & Health PHI', query: 'HIPAA', category: 'Healthcare' },
  { label: '🇪🇺 EU GDPR Art. 32', query: 'GDPR', category: 'EU' },
  { label: '💳 PCI-DSS Financial', query: 'PCI', category: 'Financial Services' },
  { label: '🤖 MCP Autonomous Tools', query: 'MCP', category: 'Production Governance' },
]

interface PostureTelemetry {
  rateLimit: string
  dlpAction: string
  cycleBreak: string
  guardrailsCount: number
  jurisdiction: string
  targetEcosystem: string
}

function getPostureTelemetry(tpl: PolicyTemplate): PostureTelemetry {
  const content = tpl.content || ''
  
  const rateMatch = content.match(/max_calls_per_second:\s*(\d+)/)
  const rateLimit = rateMatch ? `${rateMatch[1]} req/s` : '20 req/s'

  let dlpAction = 'Standard DLP'
  if (content.includes('action: "deny"') && content.includes('action: "redact"')) {
    dlpAction = 'Strict Deny & Redact'
  } else if (content.includes('action: "deny"')) {
    dlpAction = 'Strict Deny'
  } else if (content.includes('action: "redact"')) {
    dlpAction = 'Auto-Redact'
  } else if (content.includes('prompt_injection')) {
    dlpAction = 'Jailbreak & Injection Shield'
  }

  let cycleBreak = 'Protected'
  const cycleMatch = content.match(/max_attempts:\s*(\d+)/)
  if (cycleMatch) {
    cycleBreak = `Cycle Break (${cycleMatch[1]}x)`
  } else if (content.includes('cycle_detection')) {
    cycleBreak = 'Cycle Break'
  }

  const nameLower = (tpl.name || '').toLowerCase()
  const catLower = (tpl.category || '').toLowerCase()
  const catsLower = (tpl.categories || []).map(c => c.toLowerCase()).join(' ')
  
  let jurisdiction = 'Global'
  let targetEcosystem = 'Enterprise Gateway'

  if (nameLower.includes('australia') || catLower.includes('australia') || catsLower.includes('australia')) {
    jurisdiction = '🇦🇺 Australia'
    targetEcosystem = 'APRA CPS 234 / TFN'
  } else if (nameLower.includes('eu') || nameLower.includes('gdpr') || catLower.includes('eu') || catsLower.includes('eu')) {
    jurisdiction = '🇪🇺 EU'
    targetEcosystem = 'GDPR Art. 32'
  } else if (nameLower.includes('hipaa') || catLower.includes('healthcare') || catsLower.includes('healthcare')) {
    jurisdiction = '🇺🇸 US'
    targetEcosystem = 'HIPAA / PHI Safe Harbor'
  } else if (nameLower.includes('pci') || catLower.includes('financial') || catsLower.includes('financial')) {
    jurisdiction = 'Global'
    targetEcosystem = 'PCI-DSS v4.0'
  } else if (tpl.id === 'safe-cursor' || nameLower.includes('cursor')) {
    jurisdiction = 'Developer Fleet'
    targetEcosystem = 'Cursor & Cline Workstations'
  } else if (tpl.id === 'autonomous-agent-guardrails' || nameLower.includes('mcp')) {
    jurisdiction = 'Agent Mesh'
    targetEcosystem = 'Model Context Protocol (MCP)'
  } else if (nameLower.includes('singapore') || catLower.includes('singapore')) {
    jurisdiction = '🇸🇬 Singapore'
    targetEcosystem = 'PDPA / MAS FinTech'
  } else if (nameLower.includes('uae') || catLower.includes('uae')) {
    jurisdiction = '🇦🇪 UAE'
    targetEcosystem = 'Sovereign AI Framework'
  } else if (nameLower.includes('pipeda') || nameLower.includes('canada') || catLower.includes('canada')) {
    jurisdiction = '🇨🇦 Canada'
    targetEcosystem = 'PIPEDA / FIPPA'
  } else if (nameLower.includes('aviation')) {
    jurisdiction = 'Aerospace'
    targetEcosystem = 'Mission-Critical Operations'
  } else if (nameLower.includes('brand')) {
    jurisdiction = 'Global'
    targetEcosystem = 'Brand Protection'
  } else if (nameLower.includes('cost')) {
    jurisdiction = 'Global'
    targetEcosystem = 'Token & Budget Governor'
  } else if (nameLower.includes('injection') || nameLower.includes('jailbreak')) {
    jurisdiction = 'Global'
    targetEcosystem = 'Adversarial Heuristics'
  }

  return {
    rateLimit,
    dlpAction,
    cycleBreak,
    guardrailsCount: tpl.guardrails?.length || 0,
    jurisdiction,
    targetEcosystem
  }
}

export default function PolicyMarketplace() {
  const [templates, setTemplates] = useState<PolicyTemplate[]>(BUILTIN_TEMPLATES)
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategories, setSelectedCategories] = useState<string[]>([])
  const [selectedComplexity, setSelectedComplexity] = useState<string>('All')
  const [selectedDomain, setSelectedDomain] = useState<string>('all')
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid')
  
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

  // Calculate dynamic counts for each domain
  const domainCounts = useMemo(() => {
    const counts: Record<string, number> = { all: templates.length }
    DOMAIN_FILTERS.forEach(df => {
      if (df.id === 'all') return
      let c = 0
      templates.forEach(t => {
        const templateCats = [t.category, ...(t.categories || []), ...(t.tags || [])].filter(Boolean)
        const matchCat = df.matchCats?.some(cat =>
          templateCats.some(tc => tc.toLowerCase() === cat.toLowerCase())
        )
        const matchId = df.matchIds?.includes(t.id)
        const matchCustom = df.id === 'custom' && (t.is_custom || t.category === 'Custom')
        if (matchCat || matchId || matchCustom) {
          c++
        }
      })
      counts[df.id] = c
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

  // Filter templates based on Domain, Multi-Select Categories, Complexity, and Search
  const filteredTemplates = useMemo(() => {
    return (Array.isArray(templates) ? templates : []).filter(t => {
      if (!t) return false
      const name = t.name || ''
      const desc = t.description || ''
      const tags = Array.isArray(t.tags) ? t.tags : []
      const guardrails = Array.isArray(t.guardrails) ? t.guardrails : []
      const templateCats = [t.category, ...(t.categories || []), ...tags].filter(Boolean)

      // Domain Filter
      if (selectedDomain !== 'all') {
        const domain = DOMAIN_FILTERS.find(d => d.id === selectedDomain)
        if (domain) {
          const matchCat = domain.matchCats?.some(cat => 
            templateCats.some(tc => tc.toLowerCase() === cat.toLowerCase())
          )
          const matchId = domain.matchIds?.includes(t.id)
          const matchCustom = domain.id === 'custom' && (t.is_custom || t.category === 'Custom')
          if (!matchCat && !matchId && !matchCustom) {
            return false
          }
        }
      }

      // Category filter (if any selected, template must match at least one)
      if (selectedCategories.length > 0) {
        const matchesCategory = selectedCategories.some(selectedCat =>
          templateCats.some(tc => tc.toLowerCase() === selectedCat.toLowerCase())
        )
        if (!matchesCategory) return false
      }

      // Complexity filter
      if (selectedComplexity !== 'All') {
        const matchesComplexity = (t.complexity || '').toLowerCase().includes(selectedComplexity.toLowerCase())
        if (!matchesComplexity) return false
      }

      // Search filter
      const q = searchQuery.toLowerCase().trim()
      if (q) {
        const matchesSearch =
          name.toLowerCase().includes(q) ||
          desc.toLowerCase().includes(q) ||
          tags.some(tag => (tag || '').toLowerCase().includes(q)) ||
          guardrails.some(g => (g || '').toLowerCase().includes(q)) ||
          templateCats.some(c => (c || '').toLowerCase().includes(q))
        if (!matchesSearch) return false
      }

      return true
    })
  }, [templates, selectedDomain, selectedCategories, selectedComplexity, searchQuery])

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
      {/* Hero & Header Section */}
      <section className="marketplace-hero-section">
        <header className="marketplace-header">
          <div className="marketplace-title-section">
            <div className="catalog-badge-row">
              <span className="catalog-badge">VEXA SECURITY POSTURE CATALOG</span>
              <span className="live-status-pill">
                <span className="live-pulse" /> Active Fleet Enforced
              </span>
            </div>
            <h1>Policy Templates</h1>
            <p>
              Pre-configured enterprise security postures, regulatory blueprints, and zero-trust sandboxes for AI agents and LLM gateways.
            </p>
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

        {/* Posture KPI Summary Ribbon */}
        <div className="posture-kpi-ribbon">
          <div className="kpi-metric-item">
            <div className="kpi-icon">🛡️</div>
            <div className="kpi-content">
              <span className="kpi-value">{templates.length} Curated Postures</span>
              <span className="kpi-label">Ready-to-Deploy Blueprints</span>
            </div>
          </div>
          <div className="kpi-metric-item">
            <div className="kpi-icon">🏛️</div>
            <div className="kpi-content">
              <span className="kpi-value">5 Compliance Frameworks</span>
              <span className="kpi-label">APRA, HIPAA, GDPR, PCI, PDPA</span>
            </div>
          </div>
          <div className="kpi-metric-item">
            <div className="kpi-icon">💻</div>
            <div className="kpi-content">
              <span className="kpi-value">Developer & Agent Sandboxes</span>
              <span className="kpi-label">Cursor, Cline, MCP Servers</span>
            </div>
          </div>
          <div className="kpi-metric-item">
            <div className="kpi-icon">⚡</div>
            <div className="kpi-content">
              <span className="kpi-value">Zero-Downtime Deployment</span>
              <span className="kpi-label">Instant Gateway Hot-Reload</span>
            </div>
          </div>
        </div>
      </section>

      {message && (
        <div className={`message-banner ${message.type}`}>
          {message.text}
        </div>
      )}

      {/* Domain Navigation Tabs */}
      <div className="domain-nav-tabs-wrapper">
        <div className="domain-nav-tabs">
          {DOMAIN_FILTERS.map(df => {
            const count = domainCounts[df.id] || 0
            const isActive = selectedDomain === df.id
            return (
              <button
                key={df.id}
                className={`domain-tab-btn ${isActive ? 'active' : ''}`}
                onClick={() => setSelectedDomain(df.id)}
              >
                <span>{df.icon}</span>
                <span>{df.label}</span>
                <span className="domain-tab-count">{count}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Quick-Filter Presets */}
      <div className="quick-presets-bar">
        <span className="preset-title">⚡ Quick Presets:</span>
        {QUICK_PRESETS.map((p, idx) => {
          const isActive = searchQuery.toLowerCase().includes(p.query.toLowerCase())
          return (
            <button
              key={idx}
              className={`quick-preset-pill ${isActive ? 'active' : ''}`}
              onClick={() => {
                if (isActive) {
                  setSearchQuery('')
                } else {
                  setSearchQuery(p.query)
                  setSelectedDomain('all')
                }
              }}
            >
              {p.label}
            </button>
          )
        })}
        {searchQuery && (
          <button
            className="clear-link"
            style={{ marginLeft: 6 }}
            onClick={() => setSearchQuery('')}
          >
            Reset Query
          </button>
        )}
      </div>

      {/* Universal Controls Toolbar */}
      <div className="marketplace-controls-toolbar">
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

        <div className="toolbar-right-actions">
          {/* Complexity Filter Segmented Control */}
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

          {/* View Mode Toggle */}
          <div className="view-mode-toggle">
            <button
              className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
              onClick={() => setViewMode('grid')}
              title="Visual Cards Grid"
            >
              ⊞ Grid
            </button>
            <button
              className={`view-btn ${viewMode === 'table' ? 'active' : ''}`}
              onClick={() => setViewMode('table')}
              title="High-Density SOC Table"
            >
              ☰ Table
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Layout */}
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

        {/* Right Content Area */}
        <main className="marketplace-content">
          <div className="results-meta-bar">
            <span>
              Showing <strong>{filteredTemplates.length}</strong> posture template{filteredTemplates.length === 1 ? '' : 's'}
            </span>
            {(selectedCategories.length > 0 || selectedDomain !== 'all' || selectedComplexity !== 'All' || searchQuery) && (
              <div className="active-filter-pills">
                {selectedDomain !== 'all' && (
                  <span className="active-filter-pill">
                    Domain: {DOMAIN_FILTERS.find(d => d.id === selectedDomain)?.label}
                    <button onClick={() => setSelectedDomain('all')}>✕</button>
                  </span>
                )}
                {selectedComplexity !== 'All' && (
                  <span className="active-filter-pill">
                    {selectedComplexity} Complexity
                    <button onClick={() => setSelectedComplexity('All')}>✕</button>
                  </span>
                )}
                {selectedCategories.map(c => (
                  <span key={c} className="active-filter-pill">
                    {c} <button onClick={() => toggleCategory(c)}>✕</button>
                  </span>
                ))}
                {searchQuery && (
                  <span className="active-filter-pill">
                    "{searchQuery}" <button onClick={() => setSearchQuery('')}>✕</button>
                  </span>
                )}
                <button
                  className="clear-link"
                  onClick={() => {
                    setSearchQuery('')
                    clearAllCategories()
                    setSelectedComplexity('All')
                    setSelectedDomain('all')
                  }}
                >
                  Reset All
                </button>
              </div>
            )}
          </div>

          {loading ? (
            <div className="loading-state">
              <div className="spinner" />
              <p>Loading security posture blueprints...</p>
            </div>
          ) : filteredTemplates.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <h3>No templates found</h3>
              <p>No policy templates matched your active category filters or search query.</p>
              <button
                className="btn-secondary-action"
                onClick={() => {
                  setSearchQuery('')
                  clearAllCategories()
                  setSelectedComplexity('All')
                  setSelectedDomain('all')
                }}
              >
                Reset All Filters
              </button>
            </div>
          ) : viewMode === 'table' ? (
            /* SOC High-Density Table View */
            <div className="templates-table-wrapper">
              <table className="soc-postures-table">
                <thead>
                  <tr>
                    <th>Posture & Architecture</th>
                    <th>Target & Jurisdiction</th>
                    <th>Capabilities</th>
                    <th>Guardrails Enforced</th>
                    <th>Risk Level</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTemplates.map(tpl => {
                    const telemetry = getPostureTelemetry(tpl)
                    return (
                      <tr key={tpl.id} id={`template-row-${tpl.id}`}>
                        <td>
                          <div className="table-posture-info">
                            <div className={`template-card-icon ${getIconBgClass(tpl.icon, tpl.category, tpl.complexity)}`} style={{ width: 36, height: 36, fontSize: 18 }}>
                              <span>{getIconElement(tpl.icon, tpl.category)}</span>
                            </div>
                            <div>
                              <div className="table-posture-title">{tpl.name}</div>
                              <div className="table-posture-desc">{tpl.description}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="template-ecosystem-tag">
                            {telemetry.jurisdiction}
                          </span>
                          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
                            {telemetry.targetEcosystem}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 11.5 }}>
                            <span>⚡ {telemetry.rateLimit}</span>
                            <span>🔒 {telemetry.dlpAction}</span>
                          </div>
                        </td>
                        <td>
                          <div className="guardrails-list" style={{ maxWidth: 260 }}>
                            {(tpl.guardrails || []).slice(0, 2).map((g, idx) => (
                              <span key={idx} className="guardrail-pill" style={{ fontSize: 10 }}>
                                {g}
                              </span>
                            ))}
                            {(tpl.guardrails?.length || 0) > 2 && (
                              <span className="guardrail-pill-more" style={{ fontSize: 10 }}>
                                +{(tpl.guardrails?.length || 0) - 2}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className={`complexity-badge ${getComplexityClass(tpl.complexity)}`}>
                            <span className="complexity-dot" />
                            {tpl.complexity || 'Medium Complexity'}
                          </span>
                        </td>
                        <td>
                          <div className="table-actions-cell" style={{ justifyContent: 'flex-end' }}>
                            <button
                              className="btn-table-action btn-table-primary"
                              onClick={() => setSelectedActionTemplate(tpl)}
                            >
                              Use Template
                            </button>
                            <button
                              className="btn-table-action btn-table-subtle"
                              onClick={() => setPreviewTemplate(tpl)}
                              title="Preview YAML"
                            >
                              YAML
                            </button>
                            <button
                              className="btn-table-action btn-table-subtle"
                              onClick={() => handleOpenInEditor(tpl)}
                              title="Open in Policy Editor"
                            >
                              ✏️
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            /* Cards Grid View */
            <div className="templates-grid">
              {filteredTemplates.map(tpl => {
                const telemetry = getPostureTelemetry(tpl)
                return (
                  <div key={tpl.id} className="template-card" id={`template-card-${tpl.id}`}>
                    {/* Top Row: Target Ecosystem Pill + Complexity Badge */}
                    <div className="template-card-top">
                      <span className="template-ecosystem-tag">
                        {telemetry.jurisdiction} · {telemetry.targetEcosystem}
                      </span>
                      <span className={`complexity-badge ${getComplexityClass(tpl.complexity)}`}>
                        <span className="complexity-dot" />
                        {tpl.complexity || 'Medium Complexity'}
                      </span>
                    </div>

                    {/* Header: Icon + Title */}
                    <div className="template-card-header">
                      <div className={`template-card-icon ${getIconBgClass(tpl.icon, tpl.category, tpl.complexity)}`}>
                        <span>{getIconElement(tpl.icon, tpl.category)}</span>
                      </div>
                      <div style={{ flex: 1 }}>
                        <h3 className="template-title">{tpl.name}</h3>
                        <div className="template-categories-row" style={{ margin: '4px 0 0 0' }}>
                          {(tpl.categories || [tpl.category]).slice(0, 2).map((cat, idx) => (
                            <span key={idx} className="category-pill-tag">
                              {cat}
                            </span>
                          ))}
                          {tpl.is_custom && <span className="category-pill-tag custom-tag">Custom</span>}
                        </div>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="template-desc">{tpl.description}</p>

                    {/* Posture Capabilities Telemetry Grid */}
                    <div className="posture-capabilities-grid">
                      <div className="capability-item" title="Throughput limit">
                        <span className="capability-icon">⚡</span>
                        <span className="capability-text">{telemetry.rateLimit}</span>
                      </div>
                      <div className="capability-item" title="DLP protection mode">
                        <span className="capability-icon">🔒</span>
                        <span className="capability-text">{telemetry.dlpAction}</span>
                      </div>
                      <div className="capability-item" title="Firewall cycle break">
                        <span className="capability-icon">🔄</span>
                        <span className="capability-text">{telemetry.cycleBreak}</span>
                      </div>
                      <div className="capability-item" title="Enforced guardrails count">
                        <span className="capability-icon">🛡️</span>
                        <span className="capability-text">{telemetry.guardrailsCount} Guardrails</span>
                      </div>
                    </div>

                    {/* Included Guardrails Section */}
                    <div className="included-guardrails-section">
                      <span className="included-guardrails-label">ENFORCED GUARDRAILS & PROTOCOLS</span>
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
                        <span>🚀</span> Use Template
                      </button>
                      <button
                        id={`btn-preview-${tpl.id}`}
                        className="btn-preview-subtle"
                        onClick={() => setPreviewTemplate(tpl)}
                        title="Preview YAML"
                      >
                        YAML
                      </button>
                      <button
                        id={`btn-edit-${tpl.id}`}
                        className="btn-editor-shortcut"
                        onClick={() => handleOpenInEditor(tpl)}
                        title="Open in Policy Editor"
                      >
                        ✏️
                      </button>
                    </div>
                  </div>
                )
              })}
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
                <div className={`template-card-icon ${getIconBgClass(selectedActionTemplate.icon, selectedActionTemplate.category, selectedActionTemplate.complexity)}`}>
                  <span>{getIconElement(selectedActionTemplate.icon, selectedActionTemplate.category)}</span>
                </div>
                <div>
                  <h2>{selectedActionTemplate.name}</h2>
                  <span className={`complexity-badge ${getComplexityClass(selectedActionTemplate.complexity)}`}>
                    <span className="complexity-dot" />
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
                <div className="guardrails-list" style={{ marginTop: 10 }}>
                  {(selectedActionTemplate.guardrails || []).map((g, idx) => (
                    <span key={idx} className="guardrail-pill">
                      {g}
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
                    Instantly deploys this posture version to the gateway and enforces all included guardrails across live agents.
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
                    style={{ marginTop: 12, width: '100%', justifyContent: 'center' }}
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

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
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
                            <div className={`template-card-icon ${getIconBgClass(tpl.icon, tpl.category, tpl.complexity)}`} style={{ width: 34, height: 34, fontSize: 16 }}>
                              <span>{getIconElement(tpl.icon, tpl.category)}</span>
                            </div>
                            <div>
                              <h3 className="template-title" style={{ fontSize: 15, margin: 0 }}>{tpl.name}</h3>
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
                <div className={`template-card-icon ${getIconBgClass(previewTemplate.icon, previewTemplate.category, previewTemplate.complexity)}`}>
                  <span>{getIconElement(previewTemplate.icon, previewTemplate.category)}</span>
                </div>
                <div>
                  <h2>{previewTemplate.name}</h2>
                  <span className={`complexity-badge ${getComplexityClass(previewTemplate.complexity)}`}>
                    <span className="complexity-dot" />
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
                      style={{ width: '100%', padding: '10px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div>
                      <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Category</label>
                      <select
                        id="custom-template-category-select"
                        value={customCategory}
                        onChange={e => setCustomCategory(e.target.value)}
                        style={{ width: '100%', padding: '10px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#fff' }}
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
                        style={{ width: '100%', padding: '10px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#fff' }}
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
                      style={{ width: '100%', padding: '10px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#fff' }}
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
                      style={{ width: '100%', padding: '10px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#fff' }}
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
                      style={{ width: '100%', padding: '12px', background: '#07090e', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, color: '#38bdf8', fontFamily: 'monospace', fontSize: 13 }}
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

