#!/usr/bin/env bash
# ==============================================================================
# Vexa Agent Control — Small-Team Production Secret Bootstrapper (DEP-002)
# Generates cryptographically secure CSPRNG secrets and produces a hardened .env file.
# ==============================================================================
set -euo pipefail

ENV_FILE="${1:-.env}"
DOMAIN="${2:-localhost}"
ADMIN_EMAIL="${3:-admin@vexa.local}"

generate_hex() {
  local bytes="$1"
  if command -v openssl &>/dev/null; then
    openssl rand -hex "$bytes"
  else
    head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

generate_password() {
  local length="${1:-24}"
  if command -v openssl &>/dev/null; then
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c "$length"
  else
    head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c "$length"
  fi
}

echo "=========================================================="
echo "  Vexa Agent Control — CSPRNG Production Secret Bootstrapper"
echo "=========================================================="

if [[ -f "$ENV_FILE" && "${FORCE:-0}" != "1" ]]; then
  echo "[!] Target file '$ENV_FILE' already exists. Set FORCE=1 to overwrite."
  exit 1
fi

echo "[*] Generating cryptographically secure random secrets..."

POSTGRES_PASSWORD=$(generate_hex 24)
GATEWAY_SECRET=$(generate_hex 32)
POLICY_READ_SECRET=$(generate_hex 32)
PROVIDER_KEY_ENCRYPTION_SECRET=$(generate_hex 32)
SESSION_SECRET=$(generate_hex 32)
ADMIN_PASSWORD=$(generate_password 24)
INGRESS_AUTH_SECRET=$(generate_hex 32)

cat <<EOF > "$ENV_FILE"
# ==============================================================================
# Vexa Agent Control — Production Team Environment Configuration (Generated)
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# ==============================================================================

# Hub Deployment Domain
HUB_DOMAIN=${DOMAIN}

# Database Credentials
POSTGRES_USER=vexa
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=vexa_control_plane

# Internal Cluster & Gateway Secrets (32-byte CSPRNG)
GATEWAY_SECRET=${GATEWAY_SECRET}
POLICY_READ_SECRET=${POLICY_READ_SECRET}
PROVIDER_KEY_ENCRYPTION_SECRET=${PROVIDER_KEY_ENCRYPTION_SECRET}
AGENTCONTROL_SESSION_SECRET=${SESSION_SECRET}
INGRESS_AUTH_SECRET=${INGRESS_AUTH_SECRET}

# Initial Hub Administrator
SAAS_OPERATOR_EMAIL=${ADMIN_EMAIL}
SAAS_OPERATOR_PASSWORD=${ADMIN_PASSWORD}

# Strict Production Enforcement (halt boot on placeholder credentials)
DEV_MODE=false
EOF

chmod 600 "$ENV_FILE"

echo "[+] Secure production environment written to $ENV_FILE"
echo "    Admin Email    : $ADMIN_EMAIL"
echo "    Admin Password : $ADMIN_PASSWORD"
echo "    Domain         : $DOMAIN"
echo ""
echo "Next step: launch the secure team stack with:"
echo "    docker compose -f docker-compose.team.secure.yml up -d"
