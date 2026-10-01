#!/usr/bin/env bash
# ─── High-Speed Parallel Build & Deployment Automation for AgentControl Stage ───
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra/gcp"
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}"
if [ -z "$PROJECT_ID" ] && [ -f "$INFRA_DIR/terraform.stage.tfvars" ]; then
  PROJECT_ID=$(grep -E '^\s*gcp_project_id\s*=' "$INFRA_DIR/terraform.stage.tfvars" | sed -E 's/.*"([^"]+)".*/\1/' || echo "")
fi
REGION="europe-west1"
REPO_ID="agentcontrol-stage"
MACHINE_TYPE="e2-highcpu-8"

SKIP_BUILD=false
AUTO_APPROVE=false

for arg in "$@"; do
  case $arg in
    --skip-build|--use-ghcr)
      SKIP_BUILD=true
      shift
      ;;
    --auto-approve)
      AUTO_APPROVE=true
      shift
      ;;
  esac
done

START_TIME=$(date +%s)

echo "========================================================"
echo "  🛡️ AgentControl Stage High-Speed Deployment Pipeline  "
echo "========================================================"

if [ "$SKIP_BUILD" = false ]; then
  echo -e "\n[1/3] 🚀 Submitting parallel Cloud Builds ($MACHINE_TYPE)..."
  
  # Ensure Artifact Registry repository exists before pushing images
  if ! gcloud artifacts repositories describe "$REPO_ID" --project="$PROJECT_ID" --location="$REGION" >/dev/null 2>&1; then
    echo "  • Creating Artifact Registry repository '$REPO_ID' in $REGION..."
    gcloud artifacts repositories create "$REPO_ID" --repository-format=docker --location="$REGION" --project="$PROJECT_ID" --description="AgentControl $REPO_ID Container Repository" --quiet
  fi

  HAS_PERSISTENT_DB=false
  if grep -qE '^\s*database_url\s*=\s*"[^"]+"' "$INFRA_DIR/terraform.stage.tfvars" 2>/dev/null || grep -qE '^\s*enable_cloud_sql\s*=\s*true' "$INFRA_DIR/terraform.stage.tfvars" 2>/dev/null; then
    HAS_PERSISTENT_DB=true
  fi

  API_HASH=$(find "$REPO_ROOT/control-plane/api" -type f ! -path '*/node_modules/*' ! -path '*/vendor/*' ! -path '*/dist/*' -exec md5sum {} + | md5sum | cut -c1-12)
  UI_HASH=$(find "$REPO_ROOT/control-plane/ui" -type f ! -path '*/node_modules/*' ! -path '*/dist/*' -exec md5sum {} + | md5sum | cut -c1-12)
  GW_HASH=$(find "$REPO_ROOT/src" "$REPO_ROOT/benches" "$REPO_ROOT/control-plane/proto" "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" "$REPO_ROOT/Dockerfile" -type f -exec md5sum {} + | md5sum | cut -c1-12)

  API_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/dashboard-api:$API_HASH"
  UI_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/control-plane-ui:$UI_HASH"
  GW_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/agentcontrol-gateway:$GW_HASH"
  DB_IMAGE=""

  echo "  • Building API     : $API_IMAGE"
  (cd "$REPO_ROOT/control-plane/api" && gcloud builds submit . --tag "$API_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_API=$!

  echo "  • Building UI      : $UI_IMAGE"
  (cd "$REPO_ROOT/control-plane/ui" && gcloud builds submit . --tag "$UI_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_UI=$!

  echo "  • Building Gateway : $GW_IMAGE"
  (cd "$REPO_ROOT" && gcloud builds submit . --tag "$GW_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_GW=$!

  PIDS=($PID_API $PID_UI $PID_GW)

  if [ "$HAS_PERSISTENT_DB" = false ]; then
    DB_HASH=$(find "$REPO_ROOT/control-plane/db" -type f -exec md5sum {} + | md5sum | cut -c1-12)
    DB_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/agentcontrol-db:$DB_HASH"
    echo "  • Building DB      : $DB_IMAGE"
    (cd "$REPO_ROOT/control-plane/db" && gcloud builds submit . --tag "$DB_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
    PID_DB=$!
    PIDS+=($PID_DB)
  else
    echo "  • Database         : Skipped (PostgreSQL / Cloud SQL persistence active)"
  fi

  wait "${PIDS[@]}"
  echo "  ✅ All required container builds finished successfully."
fi

echo -e "\n[2/3] 🏗️ Applying Terraform with High Parallelism (-parallelism=20)..."

# Check database persistence configuration to prevent accidental data loss
if [ "${HAS_PERSISTENT_DB:-false}" = false ]; then
  echo -e "  ⚠️  \033[1;33m[DATA LOSS WARNING] Ephemeral database sidecar detected!\033[0m"
  echo -e "  Neither 'database_url' nor 'enable_cloud_sql = true' is active in terraform.stage.tfvars."
  echo -e "  Any Provider Keys, Virtual Keys, and Logs will be WIPED upon the next revision or idle scale-to-zero."
  echo -e "  To persist data permanently across deployments, set 'enable_cloud_sql = true' or provide a persistent 'database_url'.\n"
fi

cd "$INFRA_DIR"

TF_ARGS=("apply" "-var-file=terraform.stage.tfvars" "-parallelism=20")
if [ "$SKIP_BUILD" = false ]; then
  TF_ARGS+=(
    "-var=container_image=$GW_IMAGE"
    "-var=control_plane_api_image=$API_IMAGE"
    "-var=control_plane_ui_image=$UI_IMAGE"
  )
  if [ -n "$DB_IMAGE" ]; then
    TF_ARGS+=("-var=control_plane_db_image=$DB_IMAGE")
  fi
fi
if [ "$AUTO_APPROVE" = true ]; then
  TF_ARGS+=("-auto-approve")
fi

terraform "${TF_ARGS[@]}"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo -e "\n========================================================"
echo "  🎉 Deployment completed in ${DURATION}s!"
echo "========================================================"
