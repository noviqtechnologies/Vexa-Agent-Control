# Vexa Commercial Enterprise License

Copyright (c) 2026 Noviq Technologies Inc. All rights reserved.

## 1. Grant of License
Subject to the terms and conditions of this Agreement and payment of the applicable commercial license fees, Noviq Technologies Inc. grants you a non-exclusive, non-transferable, revocable license to use, install, and execute the enterprise features and software components located in this directory (`enterprise/`) and unlocked via an authorized Vexa cryptographic license token (`VEXA_LICENSE_KEY`).

## 2. Permitted Use & Gating
- **Tier Entitlements:** Capabilities including enterprise OIDC/SAML SSO, strict mTLS identity, real-time SIEM streaming (Splunk, Datadog, OpenSearch), spend governance v2, zero-knowledge CMK custody, and deep DLP redaction are governed by active tier quotas (`team` or `enterprise`).
- **Single-Tenant Deployment:** Each license token is valid for a single private organization deployment (`organization_id`) and authorizes up to the maximum enrolled device count specified in the signed token claims.
- **Air-Gapped & Offline Verification:** Signature validation executes cryptographically offline via embedded Ed25519 public keys without outbound telemetry.

## 3. Restrictions
Except as expressly authorized under an executed enterprise agreement with Noviq Technologies Inc., you may not:
1. Sub-license, lease, resell, or distribute the enterprise features as a multi-tenant hosted service to third parties.
2. Reverse engineer, tamper with, or forge cryptographic license signatures or quota validators.
3. Remove or alter any copyright, proprietary notices, or license terms in the source code or documentation.

## 4. Open-Core Distinction
Core gateway primitives, local CLI protections, MCP interception, JSONL audit logs, and single-device developer capabilities remain open source under the Apache 2.0 License in the repository root ([LICENSE](../LICENSE)).

For commercial licensing, enterprise quotes, or dedicated support agreements, contact `sales@noviqtech.com` or visit `https://noviqtech.com/enterprise`.
