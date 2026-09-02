#!/usr/bin/env bash
# ─── High-Speed Parallel Build & Deployment Automation for AgentControl Stage ───
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra/gcp"
PROJECT_ID="vexa-prod"
REGION="europe-west1"
REPO_ID="agentcontrol-stage"
MACHINE_TYPE="e2-highcpu-8"

SKIP_BUILD=false
AUTO_APPROVE=false

for arg in "$@"; do
  case $arg in
    --skip-build)
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
  
  API_HASH=$(find "$REPO_ROOT/control-plane/api" -type f ! -path '*/node_modules/*' ! -path '*/vendor/*' ! -path '*/dist/*' -exec md5sum {} + | md5sum | cut -c1-12)
  UI_HASH=$(find "$REPO_ROOT/control-plane/ui" -type f ! -path '*/node_modules/*' ! -path '*/dist/*' -exec md5sum {} + | md5sum | cut -c1-12)
  DB_HASH=$(find "$REPO_ROOT/control-plane/db" -type f -exec md5sum {} + | md5sum | cut -c1-12)
  GW_HASH=$(find "$REPO_ROOT/src" "$REPO_ROOT/benches" "$REPO_ROOT/control-plane/proto" "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" "$REPO_ROOT/Dockerfile" -type f -exec md5sum {} + | md5sum | cut -c1-12)

  API_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/dashboard-api:$API_HASH"
  UI_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/control-plane-ui:$UI_HASH"
  DB_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/agentcontrol-db:$DB_HASH"
  GW_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_ID/agentcontrol-gateway:$GW_HASH"

  echo "  • Building API     : $API_IMAGE"
  (cd "$REPO_ROOT/control-plane/api" && gcloud builds submit . --tag "$API_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_API=$!

  echo "  • Building UI      : $UI_IMAGE"
  (cd "$REPO_ROOT/control-plane/ui" && gcloud builds submit . --tag "$UI_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_UI=$!

  echo "  • Building DB      : $DB_IMAGE"
  (cd "$REPO_ROOT/control-plane/db" && gcloud builds submit . --tag "$DB_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_DB=$!

  echo "  • Building Gateway : $GW_IMAGE"
  (cd "$REPO_ROOT" && gcloud builds submit . --tag "$GW_IMAGE" --project "$PROJECT_ID" --region "$REGION" --machine-type "$MACHINE_TYPE" --timeout=10m --quiet) &
  PID_GW=$!

  wait $PID_API $PID_UI $PID_DB $PID_GW
  echo "  ✅ All container builds finished successfully."
fi

echo -e "\n[2/3] 🏗️ Applying Terraform with High Parallelism (-parallelism=20)..."
cd "$INFRA_DIR"

TF_ARGS=("apply" "-var-file=terraform.stage.tfvars" "-parallelism=20")
if [ "$SKIP_BUILD" = false ]; then
  TF_ARGS+=(
    "-var=container_image=$GW_IMAGE"
    "-var=control_plane_api_image=$API_IMAGE"
    "-var=control_plane_ui_image=$UI_IMAGE"
    "-var=control_plane_db_image=$DB_IMAGE"
  )
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
