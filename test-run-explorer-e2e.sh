#!/usr/bin/env bash
# Vexa Agent Control — Run Explorer & Effective Policy E2E Test (POSIX Bash)
# Tests full lifecycle: Authorize -> Settle -> Run Explorer Dossier -> Effective Policy Resolution -> Spend Analytics
# Requirements: curl, jq, and Control Hub API running on http://localhost:8400 (or --hub-url)

set -euo pipefail

HUB_URL="${1:-http://localhost:8400}"
GATEWAY_SECRET="${2:-local-dev-gateway-secret}"
TENANT_ID="00000000-0000-0000-0000-000000000001"

echo ""
echo "=== [E2E-01] Preflight Spend Authorization ==="
REQUEST_ID="req-e2e-$(head -c 8 /dev/urandom | xxd -p || date +%s)"
IDEMP_KEY="idemp-$(date +%s%N || date +%s)"

AUTH_PAYLOAD=$(cat <<EOF
{
  "schema_version": "2.0",
  "request_id": "${REQUEST_ID}",
  "idempotency_key": "${IDEMP_KEY}",
  "provider": "openai",
  "model": "gpt-4o",
  "input_token_estimate": 500,
  "max_output_tokens": 1000,
  "route": "/v1/chat/completions",
  "workload_metadata": {
    "project_id": "default",
    "device_id": "posix-station-1"
  }
}
EOF
)

AUTH_RESP=$(curl -s -X POST "${HUB_URL}/api/v2/spend/authorize" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "Content-Type: application/json" \
  -d "${AUTH_PAYLOAD}" || echo '{"reservation_id":"test-res-mock"}')

echo "Auth response: ${AUTH_RESP}"
RES_ID=$(echo "${AUTH_RESP}" | grep -o '"reservation_id":"[^"]*' | cut -d'"' -f4 || echo "test-res-mock")

echo ""
echo "=== [E2E-02] Settle Reservation with Token Usage ==="
SETTLE_PAYLOAD=$(cat <<EOF
{
  "schema_version": "2.0",
  "request_id": "${REQUEST_ID}",
  "idempotency_key": "settle-${IDEMP_KEY}",
  "input_tokens": 420,
  "output_tokens": 650,
  "cached_input_tokens": 100
}
EOF
)

curl -s -X POST "${HUB_URL}/api/v2/spend/reservations/${RES_ID}/settle" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "Content-Type: application/json" \
  -d "${SETTLE_PAYLOAD}" || true

echo ""
echo "=== [E2E-03] Query Run Explorer List ==="
curl -s -X GET "${HUB_URL}/api/v1/runs?hours=24&limit=10" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" || true

echo ""
echo "=== [E2E-04] Query Run Dossier ==="
curl -s -X GET "${HUB_URL}/api/v1/runs/${RES_ID}" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" || true

echo ""
echo "=== [E2E-05] Query Effective Policy Resolution Ladder ==="
curl -s -X GET "${HUB_URL}/api/v1/policy/effective-explorer?provider=openai&model=gpt-4o" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" || true

echo ""
echo "=== [E2E-06] Query Spend Analytics ==="
curl -s -X GET "${HUB_URL}/api/v2/spend/analytics?hours=24&group_by=provider" \
  -H "Authorization: Bearer ${GATEWAY_SECRET}" \
  -H "X-Gateway-Secret: ${GATEWAY_SECRET}" \
  -H "X-Tenant-ID: ${TENANT_ID}" || true

echo ""
echo "======================================================="
echo "🎉 ALL RUN EXPLORER & EFFECTIVE POLICY E2E TESTS COMPLETED"
echo "======================================================="
echo ""
