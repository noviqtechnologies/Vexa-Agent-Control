# Production Environment Example

This directory contains the production-grade deployment template for Vexa Agent Control.

## Security Guarantees & Requirements
1. **Zero Default Credentials:** All passwords, tokens, and encryption keys must be generated uniquely using cryptographically secure random sources.
2. **Fail-Closed Verification:** Production mode strictly refuses to boot if known default passwords (`admin123456`, `devpassword`, etc.) or weak short keys are supplied.
3. **Immutable Image References:** All container images are pinned by exact version tags and digests rather than `:latest`.
4. **TLS Enforcement:** All external traffic is terminated via Caddy with HTTPS on port 443.

## Generating Production Secrets
Run the following script to generate secure random keys:
```bash
# Generate 256-bit hexadecimal encryption secret
openssl rand -hex 32

# Generate secure random authentication tokens
openssl rand -base64 32
```

## Quick Start
1. Copy the template:
   ```bash
   cp .env.production.example .env
   ```
2. Populate every required variable in `.env`.
3. Launch the stack:
   ```bash
   docker compose up -d
   ```
